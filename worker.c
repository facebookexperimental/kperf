// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/errqueue.h>
#include <linux/tcp.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>

#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/minmax/minmax.h>
#include <ccan/time/time.h>

#include "cpu_stat.h"
#include "tcp.h"
#include "proto.h"
#include "proto_dbg.h"
#include "server.h"
#include "tcp.h"

/* Main worker state AKA self */
struct worker_state {
	int main_sock;
	enum kpm_rx_mode rx_mode;
	enum kpm_tx_mode tx_mode;
	int epollfd;
	unsigned int id;
	int quit;
	struct kpm_test *test;
	struct cpu_stat *cpu_start;
	struct timemono test_start;
	struct timemono prev_loop;
	unsigned int test_len_msec;
	struct list_head connections;
	struct worker_state_devmem devmem;
	bool validate;
};

struct connection {
	unsigned int id;
	int fd;
	unsigned int read_size;
	unsigned int write_size;
	__u64 to_send;
	__u64 to_send_comp;
	__u64 to_recv;
	__u64 tot_sent;
	__u64 tot_recv;
	unsigned char *rxbuf;
	struct connection_devmem devmem;
	struct kpm_test_spec *spec;
	struct tcp_info init_info;
	union {
		struct {
			unsigned int reqs;
			unsigned int hist[33];
			unsigned int log_len;
			unsigned int log_len_max;
			unsigned int *log;
		} rr;
	};
	struct list_node connections;
};

unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

static struct connection *
worker_find_connection_by_fd(struct worker_state *self, int fd)
{
	struct connection *conn;

	list_for_each(&self->connections, conn, connections) {
		if (conn->fd == fd)
			return conn;
	}
	return NULL;
}

static void
worker_kill_conn(struct worker_state *self, struct connection *conn)
{
	struct epoll_event ev = {};

	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_DEL, conn->fd, &ev) < 0)
		warn("Failed to del poll out");
	if (self->rx_mode == KPM_RX_MODE_DEVMEM)
		(void)devmem_release_tokens(conn->fd, &conn->devmem);
	if (self->tx_mode == KPM_TX_MODE_DEVMEM)
		devmem_teardown_conn(&conn->devmem);
	close(conn->fd);
	list_del(&conn->connections);
	free(conn->rxbuf);
	free(conn->rr.log);
	free(conn);
}

static int
worker_pstat_cmp(unsigned int const *a, unsigned int const *b, void *unused)
{
	return (long long int)*a - (long long int)*b;
}

static void
worker_report_pstats(struct worker_state *self, struct connection *conn,
		     struct kpm_test_result *data)
{
	if (conn->spec->arg.rr.timings < 2)
		return;

        asort(conn->rr.log, conn->rr.log_len, worker_pstat_cmp, NULL);
	data->p25 = conn->rr.log[conn->rr.log_len / 4];
	data->p50 = conn->rr.log[conn->rr.log_len / 2];
	data->p90 = conn->rr.log[(__u64)conn->rr.log_len * 90 / 100];
	data->p99 = conn->rr.log[(__u64)conn->rr.log_len * 99 / 100];
	data->p999 = conn->rr.log[(__u64)conn->rr.log_len * 999 / 1000];
	data->p9999 = conn->rr.log[(__u64)conn->rr.log_len * 9999 / 10000];
}

/* == Worker command handling == */

static void worker_report_test(struct worker_state *self)
{
	struct cpu_stat *cpu, *cpu_pct;
	struct kpm_test_results *res;
	struct connection *conn;
	unsigned int ncpus, i;
	struct timerel t;
	size_t sz;

	kpm_dbg("Reporting results");

	sz = sizeof(*res) + sizeof(res->res[0]) * self->test->n_conns;
	res = malloc(sz);
	memset(res, 0, sz);

	t = timemono_since(self->test_start);
	res->time_usec = time_to_usec(t);
	res->n_conns = self->test->n_conns;
	res->test_id = self->test->test_id;

	ncpus = get_nprocs();
	cpu = cpu_stat_snapshot(ncpus);
	cpu_stat_sub(cpu, self->cpu_start, ncpus);
	cpu_pct = cpu_stat_to_pct00(cpu, ncpus);
	free(cpu);
	for (i = 0; i < ncpus; i++) {
		res->cpu_load[i].id	 = cpu_pct[i].cpu_id;
		res->cpu_load[i].user	 = cpu_pct[i].user;
		res->cpu_load[i].system	 = cpu_pct[i].system;
		res->cpu_load[i].idle	 = cpu_pct[i].idle;
		res->cpu_load[i].iowait	 = cpu_pct[i].iowait;
		res->cpu_load[i].irq	 = cpu_pct[i].irq;
		res->cpu_load[i].sirq	 = cpu_pct[i].sirq;
	}
	free(cpu_pct);

	i = 0;
	list_for_each(&self->connections, conn, connections) {
		struct kpm_test_result *data;
		struct tcp_info info;
		socklen_t info_len;

		do {
			if (i == res->n_conns) {
				warnx("Missing connections!");
				goto skip_results;
			}
			data = &res->res[i];
			data->worker_id = self->id;
			data->connection_id = self->test->specs[i].connection_id;
			i++;
			/* Expect the connections to be in order */
		} while (conn->id != data->connection_id);

		data->type = conn->spec->type;

		info_len = sizeof(conn->init_info);
		if (getsockopt(conn->fd, IPPROTO_TCP, TCP_INFO,
			       (void *)&info, &info_len) < 0) {
			warn("Can't get TCP info");
			goto skip_results;
		}

		data->rx_bytes = conn->tot_recv;
		data->tx_bytes = conn->tot_sent;

		if (conn->spec->type == KPM_TEST_TYPE_RR)
			data->reqs = conn->rr.reqs;

		data->retrans	= info.tcpi_total_retrans -
			conn->init_info.tcpi_total_retrans;
		data->reord_seen = info.tcpi_reord_seen -
			conn->init_info.tcpi_reord_seen;
		data->rtt	= info.tcpi_rtt;
		data->rttvar	= info.tcpi_rttvar;
		data->delivered_ce = info.tcpi_delivered_ce -
			conn->init_info.tcpi_delivered_ce;
		data->snd_wnd	= info.tcpi_snd_wnd;
		data->snd_cwnd	= info.tcpi_snd_cwnd;

		if (verbose > 2)
			print_tcp_info(&info);

		memcpy(data->lat_hist, conn->rr.hist, sizeof(data->lat_hist));
		worker_report_pstats(self, conn, data);

		/* Shut down sending to let the connection drain */
		conn->to_send = 0;
	}
skip_results:

	free(self->test);
	self->test = NULL;

	kpm_send(self->main_sock, &res->hdr, sz, KPM_MSG_WORKER_TEST_RESULT);
	free(res);
}

#define KPM_HNDL(type, name)						\
	{ KPM_MSG_WORKER_ ## type,					\
	  worker_msg_ ## name,						\
	  sizeof(struct kpm_##name),					\
	  stringify(name) }

#define KPM_HNDL_GEN(type, name, gtype)					\
	{ KPM_MSG_WORKER_ ## type,					\
	  worker_msg_ ## name,						\
	  sizeof(struct __kpm_generic_##gtype),				\
	  stringify(name) }

static void
worker_msg_id(struct worker_state *self, struct kpm_header *hdr)
{
	struct __kpm_generic_u32 *id = (void *)hdr;

	self->id = id->val;
}

static void
worker_msg_test(struct worker_state *self, struct kpm_header *hdr)
{
	struct kpm_test *req = (void *)hdr;
	unsigned int i;
	int zc;

	if (self->test) {
		warn("Already running a test");
		self->quit = 1;
		return;
	}

	kpm_dbg("start test %s", req->active ? "act" : "psv");

	self->test = malloc(hdr->len);
	memcpy(self->test, req, hdr->len);

	for (i = 0; i < req->n_conns; i++) {
		struct epoll_event ev = {};
		struct connection *conn;
		socklen_t info_len;
		__u64 len;

		conn = malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->spec = &self->test->specs[i];
		conn->id = req->specs[i].connection_id;
		conn->fd = fdpass_recv(self->main_sock);

		info_len = sizeof(conn->init_info);
		if (getsockopt(conn->fd, IPPROTO_TCP, TCP_INFO,
			       (void *)&conn->init_info, &info_len) < 0) {
			warn("Can't get TCP info");
			self->quit = 1;
		}

		if (conn->spec->arg.rr.timings > 1) {
			/* Assume we can't do a round trip < 1us on avg */
			conn->rr.log_len_max =
				self->test->time_sec * 1000 * 1000;
			conn->rr.log = calloc(conn->rr.log_len_max,
					      sizeof(conn->rr.log[0]));
		}

		list_add(&self->connections, &conn->connections);

		conn->read_size = conn->spec->read_size;
		conn->write_size = conn->spec->write_size;

		conn->rxbuf = malloc(conn->read_size);
		if (!conn->rxbuf) {
			warnx("No memory");
			self->quit = 1;
			return;
		}

		if (!conn->read_size || conn->read_size > KPM_MAX_OP_CHUNK ||
		    !conn->write_size || conn->write_size > KPM_MAX_OP_CHUNK) {
			warnx("wrong size io op read:%u write:%u",
			      conn->read_size, conn->write_size);
			self->quit = 1;
			return;
		}

		switch (conn->spec->type) {
		case KPM_TEST_TYPE_STREAM:
			len = ~0ULL;
			break;
		case KPM_TEST_TYPE_RR:
			len = conn->spec->arg.rr.req_size;
			break;
		default:
			warnx("Unknown test type");
			return;
		}

		if (req->active)
			conn->to_send = len;
		else
			conn->to_recv = len;

		zc = self->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY;
		if (setsockopt(conn->fd, SOL_SOCKET, SO_ZEROCOPY, &zc, sizeof(zc))) {
			warnx("Failed to set SO_ZEROCOPY");
			self->quit = 1;
			return;
		}

		if (self->tx_mode == KPM_TX_MODE_DEVMEM) {
			if (devmem_setup_conn(conn->fd, &conn->devmem) < 0) {
				self->quit = 1;
				return;
			}
		}

		ev.events = EPOLLIN | EPOLLOUT;
		ev.data.fd = conn->fd;
		if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, conn->fd, &ev) < 0)
			warn("Failed to modify poll out");
	}

	self->cpu_start = cpu_stat_snapshot(0);
	self->test_start = time_mono();
	memset(&self->prev_loop, 0, sizeof(self->prev_loop));
	if (self->test->active)
		self->test_len_msec = req->time_sec * 1000;
}

static void
worker_msg_end_test(struct worker_state *self, struct kpm_header *hdr)
{
	struct connection *conn, *next;

	if (self->test)
		worker_report_test(self);

	free(self->cpu_start);
	self->cpu_start = NULL;
	list_for_each_safe(&self->connections, conn, next, connections)
		worker_kill_conn(self, conn);
}

static const struct {
	enum kpm_msg_type type;
	void (*cb)(struct worker_state *self, struct kpm_header *hdr);
	size_t req_size;
	const char *name;
} msg_handlers[] = {
	KPM_HNDL_GEN(ID, id, u32),
	KPM_HNDL(TEST, test),
	KPM_HNDL(END_TEST, end_test),
};

static void worker_handle_main_sock(struct worker_state *self)
{
	struct kpm_header *hdr;
	int i;

	hdr = kpm_receive(self->main_sock);
	if (!hdr) {
		__kpm_dbg("<<", "ctrl recv failed");
		self->quit = 1;
		return;
	}
	kpm_cmd_dbg_start(hdr);

	for (i = 0; i < (int)ARRAY_SIZE(msg_handlers); i++) {
		if (msg_handlers[i].type != hdr->type)
			continue;

		if (hdr->len < msg_handlers[i].req_size) {
			warn("Invalid request for %s", msg_handlers[i].name);
			self->quit = 1;
			break;
		}

		msg_handlers[i].cb(self, hdr);
		break;
	}
	if (i == (int)ARRAY_SIZE(msg_handlers)) {
		warnx("Unknown message type: %d", hdr->type);
		self->quit = 1;
	}

	kpm_cmd_dbg_end(hdr);
	free(hdr);
}

/* == Worker I/O handling == */

static void
worker_record_rr_time(struct worker_state *self, struct connection *conn)
{
	struct timerel delta;
	unsigned int nsec128;
	struct timemono now;
	int hist_idx;

	if (!conn->spec->arg.rr.timings)
		return;

	now = time_mono();
	if (!self->prev_loop.ts.tv_sec)
		goto out_update;

	delta = timemono_between(now, self->prev_loop);
	nsec128 = delta.ts.tv_nsec / 128;
	if (delta.ts.tv_sec)
		nsec128 = ~0U;

	if (conn->spec->arg.rr.timings > 1 &&
	    conn->rr.log_len < conn->rr.log_len_max)
		conn->rr.log[conn->rr.log_len++] = nsec128;

	hist_idx = 0;
	while (nsec128) {
		nsec128 >>= 1;
		hist_idx++;
	}
	conn->rr.hist[hist_idx]++;

out_update:
	self->prev_loop = now;
}

static void
worker_send_arm(struct worker_state *self, struct connection *conn,
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
worker_send_disarm(struct worker_state *self, struct connection *conn,
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
worker_send_finished(struct worker_state *self, struct connection *conn,
		     unsigned int events)
{
	worker_send_disarm(self, conn, events);
	worker_record_rr_time(self, conn);

	if (conn->spec->type != KPM_TEST_TYPE_RR)
		warnx("Done sending for non-RR test");
	else
		conn->rr.reqs++;

	if (self->test->active)
		conn->to_recv =	conn->spec->arg.rr.resp_size;
	else
		conn->to_recv =	conn->spec->arg.rr.req_size;
}

static void
worker_recv_finished(struct worker_state *self, struct connection *conn)
{
	if (!self->test)
		return;

	if (conn->spec->type != KPM_TEST_TYPE_RR)
		warnx("Done sending for non-RR test");

	if (self->test->active)
		conn->to_send =	conn->spec->arg.rr.req_size;
	else
		conn->to_send =	conn->spec->arg.rr.resp_size;
}

static void
worker_handle_completions(struct worker_state *self, struct connection *conn,
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
worker_handle_send(struct worker_state *self, struct connection *conn,
		   unsigned int events)
{
	unsigned int rep = max_t(int, 10, conn->to_send / conn->write_size + 1);
	bool msg_zerocopy = self->tx_mode == KPM_TX_MODE_SOCKET_ZEROCOPY;
	int flags = msg_zerocopy ? MSG_ZEROCOPY : 0;

	while (rep--) {
		size_t chunk;
		void *src;
		ssize_t n;

		chunk = min_t(size_t, conn->write_size, conn->to_send);

		if (self->tx_mode == KPM_TX_MODE_DEVMEM) {
			n = devmem_sendmsg(conn->fd, &conn->devmem,
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
				worker_send_arm(self, conn, events);
				return;
			}
			warn("Send failed");
			worker_kill_conn(self, conn);
			return;
		}

		conn->to_send -= n;
		conn->tot_sent += n;
		if (msg_zerocopy || self->tx_mode == KPM_TX_MODE_DEVMEM) {
			conn->to_send_comp += 1;
			kpm_dbg("queued send completion, total %d",
				conn->to_send_comp);
		}

		if (!conn->to_send && !conn->to_send_comp) {
			worker_send_finished(self, conn, events);
			break;
		}

		if (n != (ssize_t)chunk) {
			kpm_dbg("send full (partial)");
			worker_send_arm(self, conn, events);
			return;
		}
	}
}

static ssize_t worker_handle_regular_recv(struct worker_state *self, struct connection *conn, size_t chunk, int rep, bool validate)
{
	bool msg_trunc = self->rx_mode == KPM_RX_MODE_SOCKET_TRUNC;
	void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
	int flags = msg_trunc ? MSG_TRUNC : 0;
	ssize_t n;

	n = recv(conn->fd, conn->rxbuf, chunk, MSG_DONTWAIT | flags);

	if (n <= 0 || msg_trunc)
		return n;

	if (validate && memcmp(conn->rxbuf, src, n))
		warnx("Data corruption %d %d %ld %lld %lld %d",
		      *conn->rxbuf, *(char *)src, n,
		      conn->tot_recv % PATTERN_PERIOD,
		      conn->tot_recv, rep);

	return n;
}

static void
worker_handle_recv(struct worker_state *self, struct connection *conn)
{
	unsigned int rep = 10;

	while (rep--) {
		size_t chunk;
		ssize_t n;

		chunk = min_t(size_t, conn->read_size, conn->to_recv);
		if (self->rx_mode == KPM_RX_MODE_DEVMEM)
			n = devmem_recv(conn->fd, &conn->devmem,
					conn->rxbuf, chunk, &self->devmem.mem,
					rep, conn->tot_recv, self->validate);
		else
			n = worker_handle_regular_recv(self, conn, chunk, rep,
						       self->validate);
		if (n == 0) {
			warnx("zero recv");
			worker_kill_conn(self, conn);
			break;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;;
			warn("Recv failed");
			worker_kill_conn(self, conn);
			break;
		}

		conn->to_recv -= n;
		conn->tot_recv += n;

		if (!conn->to_recv) {
			worker_recv_finished(self, conn);
			if (conn->to_send) {
				worker_handle_send(self, conn, 0);
				break;
			}
		}

		if (n != conn->read_size)
			break;
	}

}

static void
worker_handle_conn(struct worker_state *self, int fd, unsigned int events)
{
	static int warnd_unexpected_pi;
	struct connection *conn;

	conn = worker_find_connection_by_fd(self, fd);

	if (events & EPOLLOUT) {
		if (conn->to_send)
			worker_handle_send(self, conn, events);
		else if (!conn->to_send_comp)
			worker_send_disarm(self, conn, events);
	}
	if (events & EPOLLIN) {
		if (conn->to_recv) {
			worker_handle_recv(self, conn);
		} else if (!warnd_unexpected_pi) {
			warnx("Unexpected POLLIN %x", events);
			warnd_unexpected_pi = 1;
		}
	}
	if (events & EPOLLERR)
		worker_handle_completions(self, conn, events);

	if (!(events & (EPOLLOUT | EPOLLIN | EPOLLERR)))
		warnx("Connection has nothing to do %x", events);
}

/* == Main loop == */

void NORETURN pworker_main(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
			   struct memory_buffer *devmem, bool validate)
{
	struct worker_state self = {
		.main_sock = fd,
		.rx_mode = rx_mode,
		.tx_mode = tx_mode,
		.validate = validate,
	};
	struct epoll_event ev, events[32];
	unsigned char j;
	int i, nfds;

	memcpy(&self.devmem.mem, devmem, sizeof(self.devmem.mem));

	list_head_init(&self.connections);

	/* Initialize the data buffer we send/receive, it must match
	 * on both ends, this is how we catch data corruption (ekhm kTLS..)
	 */
	for (i = 0, j = 0; i < (int)ARRAY_SIZE(patbuf); i++, j++) {
		j = j ?: 1;
		patbuf[i] = j;
	}

	/* Init epoll */
	self.epollfd = epoll_create1(0);
	if (self.epollfd < 0)
		err(5, "Failed to create epoll");

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(self.epollfd, EPOLL_CTL_ADD, fd, &ev) < 0)
		err(6, "Failed to init epoll");

	while (!self.quit) {
		int msec = -1;

		/* Check if we should end the test if we initiated */
		if (self.test && self.test->active) {
			struct timerel t;

			t = timemono_since(self.test_start);
			msec = self.test_len_msec - time_to_msec(t);
			if (msec < 0)
				worker_report_test(&self);
		}

		nfds = epoll_wait(self.epollfd, events, ARRAY_SIZE(events),
				  msec);
		if (nfds < 0)
			err(7, "Failed to epoll");

		for (i = 0; i < nfds; i++) {
			struct epoll_event *e = &events[i];

			if (e->data.fd == self.main_sock)
				worker_handle_main_sock(&self);
			else
				worker_handle_conn(&self, e->data.fd,
						   e->events);
		}
	}

	kpm_dbg("exiting!");
	exit(0);
}
