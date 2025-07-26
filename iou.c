// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include "iou.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <sys/socket.h>

#include <ccan/minmax/minmax.h>

#include "proto_dbg.h"

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

struct iou_state {
	struct io_uring ring;
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
	IOU_REQ_TYPE_CANCEL		= 6,
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

static void iou_conn_add_send(struct io_uring *ring, struct connection *conn)
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

static void iou_handle_send(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct connection *conn;
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

static void iou_conn_add_recv(struct io_uring *ring, struct connection *conn)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv(sqe, conn->fd, conn->rxbuf, conn->read_size, 0);
	io_uring_sqe_set_data(sqe, tag(conn, IOU_REQ_TYPE_RECV));
}

static void iou_handle_recv(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct io_uring *ring = get_ring(self);
	struct connection *conn;
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
	p.cq_entries = 512;

	ret = io_uring_queue_init_params(64, &state->ring, &p);
	if (ret)
		err(5, "Failed to create io_uring");

	msg = malloc(sizeof(*msg));
	if (!msg) {
		free(state);
		err(6, "Failed to malloc iou_kpm_msg_state");
	}

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
			case IOU_REQ_TYPE_RECV:
				iou_handle_recv(self, cqe);
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

static void iou_conn_add(struct worker_state *state, struct connection *conn)
{
	struct io_uring *ring = get_ring(state);

	if (conn->to_send)
		iou_conn_add_send(ring, conn);

	iou_conn_add_recv(ring, conn);
}

static void iou_conn_close(struct worker_state *state, struct connection *conn)
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
}
