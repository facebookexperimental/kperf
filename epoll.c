// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include "epoll.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <linux/errqueue.h>
#include <sys/mman.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/minmax/minmax.h>

#include "worker.h"
#include "devmem.h"
#include "proto_dbg.h"

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

#define ALIGN_UP(v, align) (((v) + (align) - 1) & ~((align) - 1))
#define ALIGN_PTR_UP(p, ptr_align_to)	((typeof(p))ALIGN_UP((unsigned long)(p), ptr_align_to))

/* Each thread should reserve a big enough vma to avoid
 * spinlock collisions in ptl locks.
 * This size is 2MB on x86_64, and is exported in /proc/meminfo.
 */
static unsigned long default_huge_page_size(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	unsigned long hps = 0;
	size_t linelen = 0;
	char *line = NULL;

	if (!f) {
		warnx("Failed to detect default huge page size; using 2 MB as fallback");
		return 2 * 1024 * 1024;
	}
	while (getline(&line, &linelen, f) > 0) {
		if (sscanf(line, "Hugepagesize:       %lu kB", &hps) == 1) {
			hps <<= 10;
			break;
		}
	}
	free(line);
	fclose(f);
	return hps;
}

static struct worker_connection *
ep_find_connection_by_fd(struct worker_state *self, int fd)
{
	struct worker_connection *conn;

	list_for_each(&self->connections, conn, connections) {
		if (conn->fd == fd)
			return conn;
	}
	return NULL;
}

static void
ep_conn_close(struct worker_state *self, struct worker_connection *conn)
{
	struct epoll_event ev = {};

	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_DEL, conn->fd, &ev) < 0)
		warn("Failed to del poll out");
	if (self->rx_mode == KPM_RX_MODE_DEVMEM)
		(void)devmem_release_tokens(conn->fd, &conn->devmem);
	else if (self->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
		munmap(conn->raddr, conn->rsize);
}

static void
ep_conn_add(struct worker_state *self, struct worker_connection *conn)
{
	struct epoll_event ev = {};
	int zc;

	zc = self->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY || self->tx_mode == KPM_TX_MODE_DEVMEM;
	if (setsockopt(conn->fd, SOL_SOCKET, SO_ZEROCOPY, &zc, sizeof(zc))) {
		warnx("Failed to set SO_ZEROCOPY");
		self->quit = 1;
		return;
	}

	if (self->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY) {
		size_t map_align;

		map_align = default_huge_page_size();
		conn->raddr = mmap(NULL,
			conn->read_size + map_align,
			PROT_READ,
			MAP_SHARED,
			conn->fd,
			0);
		if (conn->raddr == MAP_FAILED) {
			warnx("Failed to mmap TCP_ZEROCOPY_RECEIVE");
			self->quit = 1;
			return;
		}
		conn->addr = ALIGN_PTR_UP(conn->raddr, map_align);
		conn->rsize = conn->read_size + map_align;
	}

	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void ep_handle_main_sock(struct worker_state *self)
{
	struct kpm_header *hdr;

	hdr = kpm_receive(self->main_sock);
	if (!hdr) {
		__kpm_dbg("<<", "ctrl recv failed");
		self->quit = 1;
		return;
	}

	worker_handle_proto(self, hdr);

	free(hdr);
}

static void
ep_send_arm(struct worker_state *self, struct worker_connection *conn,
	    unsigned int events)
{
	struct epoll_event ev = {};

	if (events & EPOLLOUT)
		return;

	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void
ep_send_disarm(struct worker_state *self, struct worker_connection *conn,
	       unsigned int events)
{
	struct epoll_event ev = {};

	if (!(events & EPOLLOUT))
		return;

	ev.events = EPOLLIN;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void
ep_handle_completions(struct worker_state *self, struct worker_connection *conn,
		      unsigned int events)
{
	struct sock_extended_err *serr;
	struct msghdr msg = {};
	char control[64] = {};
	struct cmsghdr *cm;
	int ret, n;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(conn->fd, &msg, MSG_ERRQUEUE);
	if (ret < 0) {
		if (errno == EAGAIN)
			return;
		warn("failed to clean completions");
		goto kill_conn;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		warnx("failed to clean completions: truncated cmsg");
		goto kill_conn;
	}

	cm = CMSG_FIRSTHDR(&msg);
	if (!cm) {
		warnx("failed to clean completions: no cmsg");
		goto kill_conn;
	}

	if (cm->cmsg_level != SOL_IP && cm->cmsg_level != SOL_IPV6) {
		warnx("failed to clean completions: wrong level %d",
		      cm->cmsg_level);
		goto kill_conn;
	}

	if (cm->cmsg_type != IP_RECVERR && cm->cmsg_type != IPV6_RECVERR) {
		warnx("failed to clean completions: wrong type %d",
		      cm->cmsg_type);
		goto kill_conn;
	}

	serr = (void *)CMSG_DATA(cm);
	if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
		warnx("failed to clean completions: wrong origin %d",
		      serr->ee_origin);
		goto kill_conn;
	}
	if (serr->ee_errno) {
		warnx("failed to clean completions: error %d",
		      serr->ee_errno);
		goto kill_conn;
	}
	n = serr->ee_data - serr->ee_info + 1;
	conn->to_send_comp -= n;
	kpm_dbg("send complete (%d..%d) %d\n",
		serr->ee_data, serr->ee_info + 1, conn->to_send_comp);

	return;

kill_conn:
	worker_kill_conn(self, conn);
}

static void
ep_handle_send(struct worker_state *self, struct worker_connection *conn,
	       unsigned int events)
{
	unsigned int rep = max_t(int, 10, conn->to_send / conn->write_size + 1);
	bool msg_zerocopy = self->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY || self->tx_mode == KPM_TX_MODE_DEVMEM;
	int flags = msg_zerocopy ? MSG_ZEROCOPY : 0;

	while (rep--) {
		size_t chunk;
		void *src;
		ssize_t n;

		chunk = min_t(size_t, conn->write_size, conn->to_send);

		if (self->tx_mode == KPM_TX_MODE_DEVMEM) {
			n = devmem_sendmsg(conn->fd, self->opts.devmem.dmabuf_id,
					   conn->tot_sent % PATTERN_PERIOD, chunk);
		} else {
			src = &patbuf[conn->tot_sent % PATTERN_PERIOD];
			n = send(conn->fd, src, chunk, MSG_DONTWAIT | flags);
		}
		if (n == 0) {
			warnx("zero send chunk:%zd to_send:%lld to_recv:%lld",
			      chunk, conn->to_send, conn->to_recv);
			worker_kill_conn(self, conn);
			return;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				kpm_dbg("send full (0 sent)");
				ep_send_arm(self, conn, events);
				return;
			}
			warn("Send failed");
			worker_kill_conn(self, conn);
			return;
		}

		conn->to_send -= n;
		conn->tot_sent += n;
		if (msg_zerocopy) {
			conn->to_send_comp += 1;
			kpm_dbg("queued send completion, total %d",
				conn->to_send_comp);
		}

		if (!conn->to_send && !conn->to_send_comp) {
			ep_send_disarm(self, conn, events);
			worker_send_finished(self, conn);
			break;
		}

		if (n != (ssize_t)chunk) {
			kpm_dbg("send full (partial)");
			ep_send_arm(self, conn, events);
			return;
		}
	}
}

static ssize_t
ep_handle_zerocopy_recv(struct worker_state *self, struct worker_connection *conn,
			size_t chunk, int rep)
{
	void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
	struct tcp_zerocopy_receive zc;
	socklen_t len = sizeof(zc);
	ssize_t n = 0;
	int res;

	memset(&zc, 0, len);
	zc.address = (__u64)((unsigned long)conn->addr);
	zc.length = chunk;
	zc.copybuf_address = (__u64)((unsigned long)conn->rxbuf);
	zc.copybuf_len = chunk;
	res = getsockopt(conn->fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE,
			 &zc, &len);
	if (res < 0)
		return res;
	if (zc.err)
		return zc.err;

	if (zc.length) {
		if (self->validate && memcmp(conn->addr, src, zc.length))
			warnx("Data corruption %d %d %u %lld %lld %d",
			*(char *)conn->addr, *(char *)src, zc.length,
			conn->tot_recv % PATTERN_PERIOD,
			conn->tot_recv, rep);
		madvise(conn->addr, zc.length, MADV_DONTNEED);
		src = &patbuf[(conn->tot_recv + zc.length) % PATTERN_PERIOD];
		n += zc.length;
	}

	if (zc.copybuf_len) {
		if (self->validate && memcmp(conn->rxbuf, src, zc.copybuf_len))
			warnx("Data corruption %d %d %d %lld %lld %d",
			*conn->rxbuf, *(char *)src, zc.copybuf_len,
			(conn->tot_recv + n) % PATTERN_PERIOD,
			(conn->tot_recv + n), rep);
		n += zc.copybuf_len;
	}

	/* Sometimes getsockopt returns 0 for both length and copybuf_len, try
	 * again */
	return n == 0 ? -EAGAIN : n;
}

static ssize_t
ep_handle_regular_recv(struct worker_state *self, struct worker_connection *conn,
		       size_t chunk, int rep)
{
	bool msg_trunc = self->rx_mode == KPM_RX_MODE_SOCKET_TRUNC;
	void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
	int flags = msg_trunc ? MSG_TRUNC : 0;
	ssize_t n;

	n = recv(conn->fd, conn->rxbuf, chunk, MSG_DONTWAIT | flags);

	if (n <= 0 || msg_trunc)
		return n;

	if (self->validate && memcmp(conn->rxbuf, src, n))
		warnx("Data corruption %d %d %ld %lld %lld %d",
		      *conn->rxbuf, *(char *)src, n,
		      conn->tot_recv % PATTERN_PERIOD,
		      conn->tot_recv, rep);

	return n;
}

static void
ep_handle_recv(struct worker_state *self, struct worker_connection *conn)
{
	unsigned int rep = 10;

	while (rep--) {
		size_t chunk;
		ssize_t n;

		chunk = min_t(size_t, conn->read_size, conn->to_recv);
		if (self->rx_mode == KPM_RX_MODE_DEVMEM)
			n = devmem_recv(conn->fd, &conn->devmem,
					conn->rxbuf, chunk, self->opts.devmem.mem,
					rep, conn->tot_recv, self->validate);
		else if (self->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
			n = ep_handle_zerocopy_recv(self, conn, chunk, rep);
		else
			n = ep_handle_regular_recv(self, conn, chunk, rep);
		if (n == 0) {
			warnx("zero recv");
			worker_kill_conn(self, conn);
			break;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (n == -EAGAIN)
				break;
			warn("Recv failed");
			worker_kill_conn(self, conn);
			break;
		}

		conn->to_recv -= n;
		conn->tot_recv += n;

		if (!conn->to_recv) {
			worker_recv_finished(self, conn);
			if (conn->to_send) {
				ep_handle_send(self, conn, 0);
				break;
			}
		}

		if (n != conn->read_size)
			break;
	}

}

static void
ep_handle_conn(struct worker_state *self, int fd, unsigned int events)
{
	static int warnd_unexpected_pi;
	struct worker_connection *conn;

	conn = ep_find_connection_by_fd(self, fd);

	if (events & EPOLLOUT) {
		if (conn->to_send)
			ep_handle_send(self, conn, events);
		else if (!conn->to_send_comp)
			ep_send_disarm(self, conn, events);
	}
	if (events & EPOLLIN) {
		if (conn->to_recv) {
			ep_handle_recv(self, conn);
		} else if (!warnd_unexpected_pi) {
			warnx("Unexpected POLLIN %x", events);
			warnd_unexpected_pi = 1;
		}
	}
	if (events & EPOLLERR)
		ep_handle_completions(self, conn, events);

	if (!(events & (EPOLLOUT | EPOLLIN | EPOLLERR)))
		warnx("Connection has nothing to do %x", events);
}

static void ep_prep(struct worker_state *self)
{
	int fd = self->main_sock;
	struct epoll_event ev;

	self->epollfd = epoll_create1(0);
	if (self->epollfd < 0)
		err(5, "Failed to create epoll");

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, fd, &ev) < 0)
		err(6, "Failed to init epoll");
}

static void ep_wait(struct worker_state *self, int msec)
{
	struct epoll_event events[32];
	int i, nfds;

	nfds = epoll_wait(self->epollfd, events, ARRAY_SIZE(events),
				msec);
	if (nfds < 0)
		err(7, "Failed to epoll");

	for (i = 0; i < nfds; i++) {
		struct epoll_event *e = &events[i];

		if (e->data.fd == self->main_sock)
			ep_handle_main_sock(self);
		else
			ep_handle_conn(self, e->data.fd,
						e->events);
	}
}

static void ep_exit(struct worker_state *self)
{
}

static const struct io_ops epoll_io_ops = {
	.prep		= ep_prep,
	.wait		= ep_wait,
	.conn_add	= ep_conn_add,
	.conn_close	= ep_conn_close,
	.exit		= ep_exit,
};

void worker_epoll_init(struct worker_state *self)
{
	self->ops = &epoll_io_ops;
}
