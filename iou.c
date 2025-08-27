// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include "iou.h"

#include <err.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <ccan/minmax/minmax.h>

#include "proto.h"
#include "proto_dbg.h"
#include "devmem.h"
#include "worker.h"

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

#define ALIGN_UP(v, align) (((v) + (align) - 1) & ~((align) - 1))

static long page_size;

struct iou_state {
	struct io_uring ring;
	void *area_ptr;
	size_t area_size;
	__u64 area_token;
	void *rq_ptr;
	struct io_uring_zcrx_rq rq;
	size_t rq_size;
	unsigned rq_mask;
	__u32 zcrx_id;
};

struct iou_kpm_msg_state {
	struct kpm_header hdr;
	void *msg;
	ssize_t off;
};

enum iou_req_type {
	IOU_REQ_TYPE_PROTO_HDR		= 1,
	IOU_REQ_TYPE_PROTO_PLD		= 2,
	IOU_REQ_TYPE_SEND		= 3,
	IOU_REQ_TYPE_RECV		= 4,
	IOU_REQ_TYPE_RECVZC		= 5,
	IOU_REQ_TYPE_CANCEL		= 6,
	IOU_REQ_TYPE_SENDZC		= 7,
};

static void *
tag(void *ptr, enum iou_req_type x)
{
	x &= 0xf;
	return (void *)(((uintptr_t)ptr) | x);
}

static void *
untag(uintptr_t ptr)
{
	return (void *)(ptr & ~0xf);
}

static enum iou_req_type
get_tag(uintptr_t ptr)
{
	return (int)(ptr & 0xf);
}

static struct iou_state *get_iou_state(struct worker_state *state)
{
	return state->io_state;
}

static struct io_uring *get_ring(struct worker_state *state)
{
	return &get_iou_state(state)->ring;
}

static void iou_conn_add_send(struct io_uring *ring, struct worker_connection *conn)
{
	struct io_uring_sqe *sqe;
	size_t chunk;
	void *src;

	chunk = min_t(size_t, conn->write_size, conn->to_send);
	src = &patbuf[conn->tot_sent % PATTERN_PERIOD];

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send(sqe, conn->fd, src, chunk, 0);
	io_uring_sqe_set_data(sqe, tag(conn, IOU_REQ_TYPE_SEND));
}

static void iou_conn_add_sendzc(struct io_uring *ring, struct worker_connection *conn)
{
	struct io_uring_sqe *sqe;
	size_t chunk;
	void *src;

	chunk = min_t(size_t, conn->write_size, conn->to_send);
	src = &patbuf[conn->tot_sent % PATTERN_PERIOD];

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send_zc_fixed(sqe, conn->fd, src, chunk, 0, 0, 0);
	io_uring_sqe_set_data(sqe, tag(conn, IOU_REQ_TYPE_SENDZC));
}

static void iou_handle_send(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct worker_connection *conn;
	ssize_t n;

	if (self->ended)
		return;

	conn = untag(cqe->user_data);
	n = cqe->res;
	if (n <= 0) {
		warnx("Send failed");
		worker_kill_conn(self, conn);
		return;
	}

	conn->to_send -= n;
	conn->tot_sent += n;

	if (!conn->to_send)
		worker_send_finished(self, conn);
	else
		iou_conn_add_send(get_ring(self), conn);
}

static void iou_handle_sendzc(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct worker_connection *conn;
	ssize_t n;

	if (self->ended)
		return;

	conn = untag(cqe->user_data);
	if (cqe->flags & IORING_CQE_F_NOTIF) {
		if (cqe->flags & IORING_CQE_F_MORE) {
			warnx("Notification completion has F_MORE set");
			worker_kill_conn(self, conn);
		}
		return;
	}

	n = cqe->res;
	if (n <= 0) {
		warnx("Send failed");
		worker_kill_conn(self, conn);
		return;
	}

	conn->to_send -= n;
	conn->tot_sent += n;

	if (!conn->to_send)
		worker_send_finished(self, conn);
	else
		iou_conn_add_sendzc(get_ring(self), conn);
}

static void iou_conn_add_recv(struct io_uring *ring, struct worker_connection *conn)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv(sqe, conn->fd, conn->rxbuf, conn->read_size, 0);
	io_uring_sqe_set_data(sqe, tag(conn, IOU_REQ_TYPE_RECV));
}

static void iou_conn_add_recvzc(struct io_uring *ring, struct worker_connection *conn, __u32 id)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, conn->fd, NULL, 0, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	sqe->zcrx_ifq_idx = id;
	io_uring_sqe_set_data(sqe, tag(conn, IOU_REQ_TYPE_RECVZC));
}

static void iou_handle_recv(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct io_uring *ring = get_ring(self);
	struct worker_connection *conn;
	ssize_t n;
	void *src;

	if (self->ended)
		return;

	conn = untag(cqe->user_data);
	n = cqe->res;
	if (n <= 0) {
		warnx("Recv failed: %ld, to_recv: %llu", n, conn->to_recv);
		worker_kill_conn(self, conn);
		return;
	}

	src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
	if (self->validate && memcmp(conn->rxbuf, src, n))
		warnx("Data corruption %d %d %ld %lld %lld",
		      *conn->rxbuf, *(char *)src, n,
		      conn->tot_recv % PATTERN_PERIOD,
		      conn->tot_recv);

	conn->to_recv -= n;
	conn->tot_recv += n;

	if (!conn->to_recv) {
		worker_recv_finished(self, conn);
		if (conn->to_send)
			iou_conn_add_send(ring, conn);
	}

	iou_conn_add_recv(ring, conn);
}

static void iou_handle_recvzc(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct iou_state *state = get_iou_state(self);
	struct io_uring *ring = get_ring(self);
	struct io_uring_zcrx_rq *rq_ring;
	struct io_uring_zcrx_cqe* rcqe;
	struct worker_connection *conn;
	struct io_uring_zcrx_rqe *rqe;
	unsigned char *data;
	__u64 mask;
	ssize_t n;
	void *src;

	if (self->ended)
		return;

	conn = untag(cqe->user_data);
	n = cqe->res;
	if (!(cqe->flags & IORING_CQE_F_MORE)) {
		if (conn->to_recv)
			warn("Recvzc ended early");
		if (n != 0)
			warn("Recvzc final completion invalid res: %ld", n);
		worker_kill_conn(self, conn);
		return;
	}

	if (n <= 0) {
		warnx("Recv failed: %ld, to_recv: %llu", n, conn->to_recv);
		worker_kill_conn(self, conn);
		return;
	}

	rcqe = (struct io_uring_zcrx_cqe *)(cqe + 1);
	mask = (1ULL << IORING_ZCRX_AREA_SHIFT) - 1;
	data = (unsigned char *)state->area_ptr + (rcqe->off & mask);

	src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
	if (self->validate && memcmp(data, src, n))
		warnx("Data corruption %d %d %ld %lld %lld",
		      *data, *(char *)src, n,
		      conn->tot_recv % PATTERN_PERIOD,
		      conn->tot_recv);

	conn->to_recv -= n;
	conn->tot_recv += n;

	if (!conn->to_recv) {
		worker_recv_finished(self, conn);
		if (conn->to_send)
			iou_conn_add_send(ring, conn);
	}

	rq_ring = &state->rq;
	rqe = &rq_ring->rqes[rq_ring->rq_tail & state->rq_mask];
	rqe->off = (rcqe->off & ~IORING_ZCRX_AREA_MASK) | state->area_token;
	rqe->len = cqe->res;
	io_uring_smp_store_release(rq_ring->ktail, ++rq_ring->rq_tail);
}

static size_t get_rq_ring_size(unsigned int entries)
{
	size_t size;

	size = entries * sizeof(struct io_uring_zcrx_rqe);
	/* add space for the header (head/tail/etc.) */
	size += page_size;

	return ALIGN_UP(size, page_size);
}

static int iou_register_zerocopy_rx(struct worker_state *self)
{
	struct iou_state *state = get_iou_state(self);
	unsigned int ring_entries;
	size_t area_size;
	size_t ring_size;
	void *area_ptr;
	void *ring_ptr;
	int ret;

	area_size = self->opts.iou.rx_size_mb * 1024 * 1024;
	/* arbitrary ring size chosen based on rx_size_mb */
	ring_entries = (area_size / (page_size * 2));
	ring_size = get_rq_ring_size(ring_entries);

	area_ptr = mmap(NULL,
		   area_size + ring_size,
		   PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE,
		   -1,
		   0
	);
	if (area_ptr == MAP_FAILED) {
		warn("Failed to mmap zero copy receive memory");
		return -1;
	}
	struct io_uring_zcrx_area_reg area_reg = {
		.addr = (__u64)(unsigned long)area_ptr,
		.len = area_size,
		.flags = 0,
	};

	ring_ptr = (char *)area_ptr + area_size;
	struct io_uring_region_desc region_reg = {
		.user_addr = (__u64)(unsigned long)ring_ptr,
		.size = ring_size,
		.flags = IORING_MEM_REGION_TYPE_USER,
	};

	struct io_uring_zcrx_ifq_reg reg = {
		.if_idx = self->opts.iou.ifindex,
		.if_rxq = self->opts.iou.queue_id,
		.rq_entries = ring_entries,
		.area_ptr = (__u64)(unsigned long)&area_reg,
		.region_ptr = (__u64)(unsigned long)&region_reg,
	};

	ret = io_uring_register_ifq(&state->ring, &reg);
	if (ret) {
		warn("io_uring_register_ifq failed: %d", ret);
		munmap(area_ptr, area_size + ring_size);
		return ret;
	}

	state->rq.khead = (unsigned int *)((char *)ring_ptr + reg.offsets.head);
	state->rq.ktail = (unsigned int *)((char *)ring_ptr + reg.offsets.tail);
	state->rq.rqes = (struct io_uring_zcrx_rqe *)((char *)ring_ptr + reg.offsets.rqes);
	state->rq.rq_tail = 0;
	state->rq.ring_entries = reg.rq_entries;

	state->area_token = area_reg.rq_area_token;
	state->rq_mask = reg.rq_entries - 1;
	state->zcrx_id = reg.zcrx_id;

	state->area_ptr = area_ptr;
	state->rq_ptr = ring_ptr;
	state->area_size = area_size;
	state->rq_size = ring_size;

	return 0;
}

static int iou_register_zerocopy_tx(struct worker_state *self)
{
	struct iou_state *state = get_iou_state(self);
	struct iovec iov;

	iov.iov_base = patbuf;
	iov.iov_len = KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1;

	return io_uring_register_buffers(&state->ring, &iov, 1);
}

static void iou_prep(struct worker_state *self)
{
	struct iou_kpm_msg_state *msg;
	struct io_uring_params p = {};
	struct io_uring_sqe *sqe;
	struct iou_state *state;
	int ret;

	state = malloc(sizeof(*state));
	if (!state)
		err(4, "Failed to malloc iou_state");
	memset(state, 0, sizeof(*state));
	self->io_state = state;

	p.flags |= IORING_SETUP_COOP_TASKRUN;
	p.flags |= IORING_SETUP_CQSIZE;
	p.flags |= IORING_SETUP_DEFER_TASKRUN;
	p.flags |= IORING_SETUP_SINGLE_ISSUER;
	p.flags |= IORING_SETUP_SUBMIT_ALL;
	if (self->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
		p.flags |= IORING_SETUP_CQE32;
	p.cq_entries = 512;

	ret = io_uring_queue_init_params(64, &state->ring, &p);
	if (ret)
		err(5, "Failed to create io_uring");

	msg = malloc(sizeof(*msg));
	if (!msg) {
		free(state);
		err(6, "Failed to malloc iou_kpm_msg_state");
	}

	if (self->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
		if (iou_register_zerocopy_rx(self))
			err(7, "Failed to register zero copy rx");

	if (self->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY)
		if (iou_register_zerocopy_tx(self))
			err(8, "Failed to register zero copy tx");

	sqe = io_uring_get_sqe(&state->ring);
	io_uring_prep_recv(sqe, self->main_sock, &msg->hdr, sizeof(msg->hdr), MSG_PEEK | MSG_WAITALL);
	io_uring_sqe_set_data(sqe, tag(msg, IOU_REQ_TYPE_PROTO_HDR));
}

static void iou_handle_proto_hdr(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct io_uring *ring = get_ring(self);
	struct iou_kpm_msg_state *msg;
	struct io_uring_sqe *sqe;
	ssize_t n = cqe->res;

	msg = untag(cqe->user_data);
	if (n < (int)sizeof(msg->hdr)) {
		if (n)
			warn("Failed to receive header (%zd)", n);
		goto err;
	}
	if (msg->hdr.len < sizeof(msg->hdr)) {
		warnx("Invalid header length (%d)", msg->hdr.len);
		goto err;
	}

	msg->msg = malloc(msg->hdr.len);
	if (!msg->msg) {
		warnx("Failed to malloc msg");
		goto err;
	}

	msg->off = 0;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv(sqe, self->main_sock, msg->msg + msg->off, msg->hdr.len, 0);
	io_uring_sqe_set_data(sqe, tag(msg, IOU_REQ_TYPE_PROTO_PLD));

	return;

err:
	__kpm_dbg("<<", "ctrl recv failed");
	self->quit = 1;
	free(msg);
	return;
}

static void iou_handle_proto_pld(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct io_uring *ring = get_ring(self);
	struct iou_kpm_msg_state *msg;
	struct io_uring_sqe *sqe;
	ssize_t n = cqe->res;

	msg = untag(cqe->user_data);
	if (n > msg->hdr.len) {
		warnx("Oversized recv");
		goto err;
	} else if (n <= 0) {
		warnx("Short recv");
		goto err;
	}

	msg->off += n;
	msg->hdr.len -= n;

	if (msg->hdr.len) {
		sqe = io_uring_get_sqe(ring);
		io_uring_prep_recv(sqe, self->main_sock, msg->msg + msg->off, msg->hdr.len, 0);
		io_uring_sqe_set_data(sqe, tag(msg, IOU_REQ_TYPE_PROTO_PLD));
		return;
	}

	worker_handle_proto(self, msg->msg);

	free(msg->msg);
	memset(msg, 0, sizeof(*msg));

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv(sqe, self->main_sock, &msg->hdr, sizeof(msg->hdr), MSG_PEEK | MSG_WAITALL);
	io_uring_sqe_set_data(sqe, tag(msg, IOU_REQ_TYPE_PROTO_HDR));

	return;
err:
	__kpm_dbg("<<", "ctrl recv failed");
	self->quit = 1;
	free(msg->msg);
	free(msg);
	return;
}

static void iou_wait(struct worker_state *self, int msec)
{
	struct io_uring *ring = get_ring(self);
	struct __kernel_timespec timeout;
	struct io_uring_cqe *cqe;
	unsigned int count = 0;
	unsigned int head;

	timeout.tv_sec = msec / 1000;
	timeout.tv_nsec = (msec % 1000) * 1000000;

	io_uring_submit_and_wait_timeout(ring, &cqe, 1, &timeout, NULL);

	io_uring_for_each_cqe(ring, head, cqe) {
		switch (get_tag(cqe->user_data)) {
			case IOU_REQ_TYPE_PROTO_HDR:
				iou_handle_proto_hdr(self, cqe);
				break;
			case IOU_REQ_TYPE_PROTO_PLD:
				iou_handle_proto_pld(self, cqe);
				break;
			case IOU_REQ_TYPE_SEND:
				iou_handle_send(self, cqe);
				break;
			case IOU_REQ_TYPE_SENDZC:
				iou_handle_sendzc(self, cqe);
				break;
			case IOU_REQ_TYPE_RECV:
				iou_handle_recv(self, cqe);
				break;
			case IOU_REQ_TYPE_RECVZC:
				iou_handle_recvzc(self, cqe);
				break;
			case IOU_REQ_TYPE_CANCEL:
				break;
			default:
				err(1, "Unknown io_uring request type: %d, res: %d", get_tag(cqe->user_data), cqe->res);
		}

		count++;
	}
	io_uring_cq_advance(ring, count);
}

static void iou_conn_add(struct worker_state *state, struct worker_connection *conn)
{
	struct io_uring *ring = get_ring(state);

	if (conn->to_send) {
		if (state->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY)
			iou_conn_add_sendzc(ring, conn);
		else
			iou_conn_add_send(ring, conn);
	}

	if (state->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
		iou_conn_add_recvzc(ring, conn, get_iou_state(state)->zcrx_id);
	else
		iou_conn_add_recv(ring, conn);
}

static void iou_conn_close(struct worker_state *state, struct worker_connection *conn)
{
	struct io_uring *ring = get_ring(state);
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel_fd(sqe, conn->fd, 0);
	io_uring_sqe_set_data(sqe, tag(NULL, IOU_REQ_TYPE_CANCEL));
	/* Cancellation is sync. A completion is always generated by the time
	 * submit returns */
	io_uring_submit(ring);
}

static void iou_exit(struct worker_state *self)
{
	struct iou_state *state = get_iou_state(self);
	struct io_uring *ring = get_ring(self);
	if (state->area_ptr)
		munmap(state->area_ptr, state->area_size + state->rq_size);
	io_uring_queue_exit(ring);
	free(self->io_state);
}

static const struct io_ops iou_io_ops = {
	.prep		= iou_prep,
	.wait		= iou_wait,
	.conn_add	= iou_conn_add,
	.conn_close	= iou_conn_close,
	.exit		= iou_exit,
};

void worker_iou_init(struct worker_state *self)
{
	self->ops = &iou_io_ops;
	page_size = sysconf(_SC_PAGESIZE);
}

int iou_zerocopy_rx_setup(struct session_state_iou *iou, int fd,
			  int num_queues)
{
	return reserve_queues(fd, num_queues, iou->ifname, &iou->ifindex,
			      &iou->queue_id, &iou->rss_context);
}

int iou_zerocopy_rx_teardown(struct session_state_iou *iou)
{
	unreserve_queues(iou->ifname, iou->rss_context);
	return 0;
}
