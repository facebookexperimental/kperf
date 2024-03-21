// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>

#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/minmax/minmax.h>

#include "proto.h"
#include "proto_dbg.h"
#include "server.h"
#include "devmem.h"
#include "iou.h"

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

struct session_state {
	int main_sock;
	int epollfd;
	int quit;
	int tcp_sock;
	enum kpm_rx_mode rx_mode;
	enum kpm_tx_mode tx_mode;
	unsigned int connection_ids;
	unsigned int worker_ids;
	unsigned int test_ids;
	struct list_head connections;
	struct list_head workers;
	struct list_head tests;
	struct session_state_devmem devmem;
	struct session_state_iou iou_state;
	bool validate;
	bool iou;
};

struct connection {
	unsigned int id;
	int fd;
	int cpu;
	int worker_fd;
	unsigned int tls_mask;
	struct list_node connections;
};

struct worker {
	unsigned int id;
	int fd;
	pid_t pid;
	int busy;
	struct list_node workers;
};

struct test {
	unsigned int id;
	int active;
	unsigned int min_worker_id;
	unsigned int worker_range;
	unsigned int workers_total;
	unsigned int workers_done;
	struct kpm_test *req, **fwd;
	struct kpm_test_results **results;
	struct list_node tests;
};

static struct connection *
session_find_connection_by_id(struct session_state *self, unsigned int id)
{
	struct connection *conn;

	list_for_each(&self->connections, conn, connections) {
		if (conn->id == id)
			return conn;
	}
	return NULL;
}

static struct worker *
session_find_worker_by_id(struct session_state *self, unsigned int id)
{
	struct worker *wrk;

	list_for_each(&self->workers, wrk, workers) {
		if (wrk->id == id)
			return wrk;
	}
	return NULL;
}

static struct test *
session_find_test_by_id(struct session_state *self, unsigned int id)
{
	struct test *test;

	list_for_each(&self->tests, test, tests) {
		if (test->id == id)
			return test;
	}
	return NULL;
}

static void session_new_conn(struct session_state *self, int fd)
{
	struct kpm_connection_id *id;
	struct connection *conn;
	socklen_t len;

	conn = malloc(sizeof(*conn));
	if (!conn)
		goto err_close;
	memset(conn, 0, sizeof(*conn));

	conn->id = ++self->connection_ids;
	conn->fd = fd;

	len = sizeof(conn->cpu);
	if (getsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &conn->cpu, &len) < 0) {
		warn("Failed to read CPU for socket");
		goto err_free;
	}

	id = kpm_receive(fd);
	if (!id) {
		warnx("No connection ID");
		goto err_free;
	}

	if (!kpm_good_req(id, KPM_MSG_TYPE_CONNECTION_ID)) {
		warnx("Invalid connection ID %d %d", id->hdr.type, id->hdr.len);
		goto err_free_id;
	}

	if (kpm_reply_conn_id(fd, &id->hdr, conn->id, conn->cpu) < 0)
		goto err_free_id;
	free(id);

	list_add(&self->connections, &conn->connections);
	return;

err_free_id:
	free(id);
err_free:
	free(conn);
err_close:
	close(fd);
	return;
}

static void
server_msg_tcp_acceptor(struct session_state *self, struct kpm_header *req)
{
	struct epoll_event ev = {};
	struct sockaddr_in6 addr;
	socklen_t len;
	int ret;

	if (self->tcp_sock) {
		kpm_reply_error(self->main_sock, req, EBUSY);
		return;
	}

	len = sizeof(addr);
	if (getsockname(self->main_sock, (void *)&addr, &len)) {
		warn("Failed to get sock type for main sock");
		self->quit = 1;
		return;
	}
	addr.sin6_port = 0;

	self->tcp_sock = socket(addr.sin6_family, SOCK_STREAM, 0);
	if (self->tcp_sock < 0) {
		warn("Failed to open socket");
		self->quit = 1;
		return;
	}

	ret = bind(self->tcp_sock, (void *)&addr, sizeof(addr));
	if (ret < 0) {
		warn("Failed to bind socket");
		self->quit = 1;
		return;
	}

	ret = listen(self->tcp_sock, 10);
	if (ret < 0) {
		warn("Failed to listen on socket");
		self->quit = 1;
		return;
	}

	len = sizeof(addr);
	if (getsockname(self->tcp_sock, (void *)&addr, &len)) {
		warn("Failed to get sock type for main sock");
		self->quit = 1;
		return;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = self->tcp_sock;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, self->tcp_sock, &ev) < 0) {
		warn("Failed to add tcp sock to epoll");
		self->quit = 1;
		return;
	}

	if (kpm_reply_acceptor(self->main_sock, req, &addr, len) < 1) {
		warn("Failed reply in %s", __func__);
		self->quit = 1;
		return;
	}
}

static void
server_msg_connect(struct session_state *self, struct kpm_header *hdr)
{
	unsigned short local_port, remote_port;
	struct kpm_connection_id *id;
	struct sockaddr_in6 addr;
	struct kpm_connect *req;
	struct connection *conn;
	socklen_t len;
	int ret, cfd;

	if (hdr->len < sizeof(struct kpm_connect)) {
		warn("Invalid request in %s", __func__);
		self->quit = 1;
		return;
	}
	req = (void *)hdr;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		self->quit = 1;
		return;
	}
	memset(conn, 0, sizeof(*conn));

	cfd = socket(req->addr.sin6_family, SOCK_STREAM, 0);
	if (cfd < 0) {
		warn("Failed to open socket");
		goto err_free;
	}

	if (req->mss &&
	    setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG,
		       (void *)&req->mss, sizeof(req->mss))) {
		warn("Setting mss failed");
		goto err_close;
	}

	if (self->tx_mode == KPM_TX_MODE_DEVMEM &&
	    devmem_bind_socket(&self->devmem, cfd) < 0)
		goto err_close;

	ret = connect(cfd, (void *)&req->addr, req->len);
	if (ret < 0) {
		warn("Failed to connect");
		goto err_close;
	}

	ret = kpm_send_conn_id(cfd, 0, 0);
	if (ret < 0) {
		warn("Failed to send connection ID");
		goto err_close;
	}

	id = kpm_receive(cfd);
	if (!id) {
		warnx("No connection ID");
		goto err_close;
	}

	if (!kpm_good_reply(id, KPM_MSG_TYPE_CONNECTION_ID, ret)) {
		warnx("Invalid connection ID %d %d", id->hdr.type, id->hdr.len);
		goto err_free_id;
	}

	conn->id = ++self->connection_ids;
	conn->fd = cfd;

	len = sizeof(conn->cpu);
	if (getsockopt(cfd, SOL_SOCKET, SO_INCOMING_CPU, &conn->cpu, &len) < 0) {
		warn("Failed to read CPU for socket");
		goto err_free_id;
	}

	len = sizeof(addr);
	if (getsockname(cfd, &addr, &len)) {
		warn("Failed to read address of socket");
		goto err_free_id;
	}
	local_port = ntohs(addr.sin6_port);

	len = sizeof(addr);
	if (getpeername(cfd, &addr, &len)) {
		warn("Failed to read address of socket");
		goto err_free_id;
	}
	remote_port = ntohs(addr.sin6_port);

	if (kpm_reply_connect(self->main_sock, hdr,
			      conn->id, conn->cpu, local_port,
			      id->id, id->cpu, remote_port) < 1) {
		warn("Failed to reply");
		goto err_free_id;
	}

	list_add(&self->connections, &conn->connections);
	free(id);

	return;

err_free_id:
	free(id);
err_close:
	close(cfd);
err_free:
	free(conn);
	self->quit = 1;
	return;
}

static void
server_msg_disconnect(struct session_state *self, struct kpm_header *hdr)
{
	struct __kpm_generic_u32 *req;
	struct connection *conn;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		goto err_quit;
	}
	req = (void *)hdr;

	conn = session_find_connection_by_id(self, req->val);
	if (!conn) {
		warnx("connection not found");
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		goto err_quit;
	}

	kpm_trace("close %d", conn->fd);
	close(conn->fd);
	list_del(&conn->connections);
	free(conn);

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		warnx("Reply failed");
		goto err_quit;
	}

	return;

err_quit:
	self->quit = 1;
}

static void
server_msg_tls(struct session_state *self, struct kpm_header *hdr)
{
	struct connection *conn;
	struct kpm_tls *req;
	int one = 1;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		goto err_quit;
	}
	req = (void *)hdr;

	if (req->dir_mask & ~(KPM_TLS_ULP | KPM_TLS_TX | KPM_TLS_RX |
			      KPM_TLS_NOPAD)) {
		warnx("unknown TLS flag");
		kpm_reply_error(self->main_sock, hdr, EINVAL);
		goto err_quit;
	}

	conn = session_find_connection_by_id(self, req->connection_id);
	if (!conn) {
		warnx("connection not found");
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		goto err_quit;
	}

	if (conn->tls_mask & req->dir_mask) {
		warnx("TLS already set");
		kpm_reply_error(self->main_sock, hdr, EBUSY);
		goto err_quit;
	}

	if (!((conn->tls_mask | req->dir_mask) & KPM_TLS_ULP)) {
		warnx("TLS ULP not requested");
		kpm_reply_error(self->main_sock, hdr, EINVAL);
		goto err_quit;
	}

	if ((req->dir_mask & KPM_TLS_ULP) &&
	    setsockopt(conn->fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		warn("TLS ULP setup failed");
		goto err_repl_errno;
	}

	if ((req->dir_mask & KPM_TLS_TX) &&
	    setsockopt(conn->fd, SOL_TLS, TLS_TX,
		       (void *)&req->info, req->len)) {
		warn("TLS Tx setup failed");
		goto err_repl_errno;
	}

	if ((req->dir_mask & KPM_TLS_RX) &&
	    setsockopt(conn->fd, SOL_TLS, TLS_RX,
		       (void *)&req->info, req->len)) {
		warn("TLS Rx setup failed");
		goto err_repl_errno;
	}

	if ((req->dir_mask & KPM_TLS_NOPAD) &&
	    setsockopt(conn->fd, SOL_TLS, TLS_RX_EXPECT_NO_PAD,
		       (void *)&one, sizeof(one))) {
		warn("TLS nopad setup failed");
		goto err_repl_errno;
	}

	conn->tls_mask = req->dir_mask;

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		warnx("Reply failed");
		goto err_quit;
	}

	return;

err_repl_errno:
	kpm_reply_error(self->main_sock, hdr, errno);
err_quit:
	self->quit = 1;
}

static void
server_msg_max_pacing(struct session_state *self, struct kpm_header *hdr)
{
	struct kpm_max_pacing *req;
	struct connection *conn;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		goto err_quit;
	}
	req = (void *)hdr;

	conn = session_find_connection_by_id(self, req->id);
	if (!conn) {
		warnx("connection not found");
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		goto err_quit;
	}

	if (setsockopt(conn->fd, SOL_SOCKET, SO_MAX_PACING_RATE,
		       &req->max_pacing, sizeof(req->max_pacing))) {
		warn("setting pacing rate failed");
		goto err_repl_errno;
	}

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		warnx("Reply failed");
		goto err_quit;
	}

	return;

err_repl_errno:
	kpm_reply_error(self->main_sock, hdr, errno);
err_quit:
	self->quit = 1;
}

static void
server_msg_tcp_cc(struct session_state *self, struct kpm_header *hdr)
{
	struct connection *conn;
	struct kpm_tcp_cc *req;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		goto err_quit;
	}
	req = (void *)hdr;

	conn = session_find_connection_by_id(self, req->id);
	if (!conn) {
		warnx("connection not found");
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		goto err_quit;
	}

	if (setsockopt(conn->fd, IPPROTO_TCP, TCP_CONGESTION, &req->cc_name,
		       strnlen(req->cc_name, sizeof(req->cc_name)))) {
		warn("setting TCP cong contorl failed");
		goto err_repl_errno;
	}

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		warnx("Reply failed");
		goto err_quit;
	}

	return;

err_repl_errno:
	kpm_reply_error(self->main_sock, hdr, errno);
err_quit:
	self->quit = 1;
}

static void
server_msg_mode(struct session_state *self, struct kpm_header *hdr)
{
	struct kpm_mode *req;
	int ret;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		goto err_quit;
	}
	req = (void *)hdr;

	if (self->tcp_sock && req->rx_mode == KPM_RX_MODE_DEVMEM) {
		ret = devmem_setup(&self->devmem, self->tcp_sock, req->dmabuf_rx_size_mb,
				   req->num_rx_queues, req->rx_provider,
				   &req->dev);
		if (ret < 0) {
			warnx("Failed to setup devmem");
			self->quit = 1;
			return;
		}
	}
	if (self->tcp_sock && req->iou && req->rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY) {
		ret = iou_zerocopy_rx_setup(&self->iou_state, self->tcp_sock, req->num_rx_queues);
		if (ret < 0) {
			warnx("Failed to setup io_uring zero copy receive");
			self->quit = 1;
			return;
		}
	}

	self->rx_mode = req->rx_mode;
	self->tx_mode = req->tx_mode;
	self->validate = req->validate;
	self->iou = req->iou;
	self->iou_state.rx_size_mb = req->iou_rx_size_mb;

	if (!self->tcp_sock && (req->tx_mode == KPM_TX_MODE_DEVMEM)) {
		ret = devmem_setup_tx(&self->devmem, req->tx_provider, req->dmabuf_tx_size_mb,
				      &req->dev, &req->addr);
		if (ret < 0) {
			warnx("Failed to setup devmem tx");
			self->quit = 1;
			return;
		}
	}

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		warnx("Reply failed");
		goto err_quit;
	}

	return;

err_quit:
	self->quit = 1;
}

static void
server_msg_spawn_worker(struct session_state *self, struct kpm_header *hdr)
{
	struct worker_opts *opts = NULL;
	struct worker *wrk = NULL;
	struct epoll_event ev = {};
	int p[2], dmabuf_id;
	pthread_attr_t attr;
	pthread_t thread;

	wrk = malloc(sizeof(*wrk));
	if (!wrk) {
		self->quit = 1;
		return;
	}
	memset(wrk, 0, sizeof(*wrk));

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, p) < 0) {
		warnx("Failed to create socket pair");
		goto err_free;
	}

	if (pthread_attr_init(&attr)) {
		warnx("Failed to init pthread attr");
		goto err_free;
	}
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		warnx("Failed to set pthread attr");
		goto err_free_attr;
	}
	dmabuf_id = self->devmem.tx_mem ? self->devmem.tx_mem->dmabuf_id : -1;
	opts = malloc(sizeof(*opts));
	if (!opts)
		goto err_free_attr;
	memset(opts, 0, sizeof(*opts));
	opts->fd = p[1];
	opts->rx_mode = self->rx_mode;
	opts->tx_mode = self->tx_mode;
	opts->validate = self->validate;
	opts->use_iou = self->iou;
	opts->devmem.mem = self->devmem.mem;
	opts->devmem.dmabuf_id = dmabuf_id;
	opts->iou.rx_size_mb = self->iou_state.rx_size_mb;
	opts->iou.ifindex = self->iou_state.ifindex;
	opts->iou.queue_id = self->iou_state.queue_id;
	if (pthread_create(&thread, &attr, worker_main, opts) != 0) {
		warnx("Failed to create worker thread");
		free(opts);
		goto err_free_attr;
	}

	self->iou_state.queue_id++;
	wrk->id = ++self->worker_ids;
	wrk->fd = p[0];

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = wrk->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, wrk->fd, &ev) < 0) {
		warnx("Failed to add worker sock to epoll");
		goto err_worker_kill;
	}

	kpm_send_u32(wrk->fd, KPM_MSG_WORKER_ID, wrk->id);

	if (kpm_reply_u32(self->main_sock, hdr, wrk->id) < 1)
		goto err_worker_kill;

	list_add(&self->workers, &wrk->workers);
	pthread_attr_destroy(&attr);

	return;

err_worker_kill:
	kpm_send_empty(wrk->fd, KPM_MSG_WORKER_KILL);
err_free_attr:
	pthread_attr_destroy(&attr);
err_free:
	free(wrk);
	self->quit = 1;
}

static void
server_msg_pin_worker(struct session_state *self, struct kpm_header *hdr)
{
	struct kpm_pin_worker *req;
	struct worker *wrk;
	cpu_set_t set;

	if (hdr->len < sizeof(struct kpm_pin_worker)) {
		warn("Invalid request in %s", __func__);
		self->quit = 1;
		return;
	}
	req = (void *)hdr;

	wrk = session_find_worker_by_id(self, req->worker_id);
	if (!wrk) {
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		return;
	}

	CPU_ZERO(&set);
	if (req->cpu == (unsigned int)-1) {
		int i, n;

		n = sysconf(_SC_NPROCESSORS_CONF);
		if (n < 0) {
			warn("Failed to get CPU count");
			kpm_reply_error(self->main_sock, hdr, errno);
			return;
		}

		for (i = 0; i < n; i++)
			CPU_SET(i, &set);
	} else {
		CPU_SET(req->cpu, &set);
	}

	if (sched_setaffinity(wrk->pid, sizeof(set), &set) < 0) {
		warn("Failed to pin worker to CPU");
		kpm_reply_error(self->main_sock, hdr, errno);
		return;
	}

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		self->quit = 1;
		return;
	}
}

static void
server_msg_test(struct session_state *self, struct kpm_header *hdr)
{
	unsigned int i, j, min_wrk, max_wrk;
	struct kpm_test *req, **fwd;
	unsigned int n_conns;
	struct test *test;

	if (hdr->len < sizeof(struct kpm_test)) {
bad_req:
		warnx("Invalid request in %s: %d < %zd",
		      __func__, hdr->len, sizeof(*req));
		self->quit = 1;
		return;
	}
	req = (void *)hdr;

	n_conns = hdr->len - sizeof(struct kpm_test);
	if (n_conns % sizeof(struct kpm_test_spec))
		goto bad_req;

	n_conns /= sizeof(struct kpm_test_spec);
	if (req->test_id || !req->time_sec || n_conns != req->n_conns)
		goto bad_req;

	test = malloc(sizeof(*test));
	memset(test, 0, sizeof(*test));

	test->id = ++self->test_ids;
	test->active = req->active;

	min_wrk = -1;
	max_wrk = 0;
	for (i = 0; i < n_conns; i++) {
		min_wrk = min(min_wrk, req->specs[i].worker_id);
		max_wrk = max(max_wrk, req->specs[i].worker_id);
	}
	test->worker_range = max_wrk - min_wrk + 1;

	fwd = calloc(test->worker_range, sizeof(void *));
	for (i = 0; i < n_conns; i++)
		fwd[i] = calloc(1, hdr->len);
	test->results = calloc(test->worker_range, sizeof(*test->results));

	for (i = 0; i < n_conns; i++) {
		struct kpm_test_spec *t = &req->specs[i];
		struct connection *conn;
		struct worker *wrk;
		struct kpm_test *msg;

		wrk = session_find_worker_by_id(self, t->worker_id);
		conn = session_find_connection_by_id(self, t->connection_id);
		if (!wrk || !conn) {
			warnx("worker or connection not found");
			kpm_reply_error(self->main_sock, hdr, ENOENT);
			goto err_free;
		}
		if (wrk->busy) {
			warnx("worker is busy");
			kpm_reply_error(self->main_sock, hdr, EBUSY);
			goto err_free;
		}

		msg = fwd[t->worker_id - min_wrk];
		memcpy(&msg->specs[msg->n_conns++], t, sizeof(*t));
	}

	for (i = 0; i < test->worker_range; i++) {
		struct connection *conn;
		struct worker *wrk;
		struct kpm_test *msg;

		msg = fwd[i];
		if (!msg->n_conns)
			continue;
		msg->active = req->active;
		msg->time_sec = req->time_sec;
		msg->test_id = test->id;

		test->workers_total++;
		wrk = session_find_worker_by_id(self, msg->specs[0].worker_id);
		wrk->busy = 1;

		kpm_send(wrk->fd, &msg->hdr,
			 sizeof(*msg) + sizeof(msg->specs[0]) * msg->n_conns,
			 KPM_MSG_WORKER_TEST);
		for (j = 0; j < msg->n_conns; j++) {
			conn = session_find_connection_by_id(self, msg->specs[j].connection_id);
			fdpass_send(wrk->fd, conn->fd);
		}
	}

	test->req = kpm_msg_dup(hdr);
	test->fwd = fwd;
	test->min_worker_id = min_wrk;
	list_add(&self->tests, &test->tests);
	kpm_reply_u32(self->main_sock, hdr, test->id);

	return;

err_free:
	free(fwd);
	self->quit = 1;
	return;
}

static void
server_msg_end_test(struct session_state *self, struct kpm_header *hdr)
{
	struct kpm_end_test *req;
	struct test *test;
	unsigned int i;

	if (hdr->len < sizeof(*req)) {
		warn("Invalid request in %s", __func__);
		self->quit = 1;
		return;
	}
	req = (void *)hdr;

	test = session_find_test_by_id(self, req->id);
	if (!test) {
		warn("Failed to find test");
		kpm_reply_error(self->main_sock, hdr, ENOENT);
		return;
	}

	if (test->active && test->workers_total != test->workers_done) {
		warn("Early test termination not supported");
		kpm_reply_error(self->main_sock, hdr, EBUSY);
		return;
	}

	for (i = 0; i < test->worker_range; i++) {
		struct worker *wrk;
		struct kpm_test *msg;

		msg = test->fwd[i];
		if (!msg->n_conns) {
			warnx("no conns on %d", i);
			continue;
		}

		kpm_trace("searching for worker %d", msg->specs[0].worker_id);
		wrk = session_find_worker_by_id(self, msg->specs[0].worker_id);
		wrk->busy = 0;

		kpm_trace("Sending end test to worker");
		kpm_send_u32(wrk->fd, KPM_MSG_WORKER_END_TEST, req->id);
	}

	if (kpm_reply_empty(self->main_sock, hdr) < 1) {
		self->quit = 1;
		return;
	}
}

static void session_handle_main_sock(struct session_state *self)
{
	struct kpm_header *hdr;

	hdr = kpm_receive(self->main_sock);
	if (!hdr) {
		__kpm_dbg("<<", "ctrl recv failed");
		self->quit = 1;
		return;
	}
	kpm_cmd_dbg_start(hdr);

	switch (hdr->type) {
	case KPM_MSG_TYPE_OPEN_TCP_ACCEPTOR:
		server_msg_tcp_acceptor(self, hdr);
		break;
	case KPM_MSG_TYPE_CONNECT:
		server_msg_connect(self, hdr);
		break;
	case KPM_MSG_TYPE_DISCONNECT:
		server_msg_disconnect(self, hdr);
		break;
	case KPM_MSG_TYPE_TLS:
		server_msg_tls(self, hdr);
		break;
	case KPM_MSG_TYPE_MAX_PACING:
		server_msg_max_pacing(self, hdr);
		break;
	case KPM_MSG_TYPE_TCP_CC:
		server_msg_tcp_cc(self, hdr);
		break;
	case KPM_MSG_TYPE_MODE:
		server_msg_mode(self, hdr);
		break;
	case KPM_MSG_TYPE_SPAWN_WORKER:
		server_msg_spawn_worker(self, hdr);
		break;
	case KPM_MSG_TYPE_PIN_WORKER:
		server_msg_pin_worker(self, hdr);
		break;
	case KPM_MSG_TYPE_TEST:
		server_msg_test(self, hdr);
		break;
	case KPM_MSG_TYPE_END_TEST:
		server_msg_end_test(self, hdr);
		break;
	default:
		warnx("Unknown message type: %d", hdr->type);
		self->quit = 1;
		break;
	}

	kpm_cmd_dbg_end(hdr);
	free(hdr);
}

static void
session_results_assemble(struct session_state *self, struct test *test)
{
	struct kpm_test_results *reply;
	unsigned int i, j;
	size_t sz;

	if (!test->results[0]) {
		warnx("First result slot empty!");
		return;
	}

	sz = sizeof(*reply) + test->req->n_conns * sizeof(reply->res[0]);
	reply = calloc(1, sz);
	memcpy(reply, test->results[0], sizeof(*reply));

	for (i = 0; i < test->req->n_conns; i++) {
		struct kpm_test_result *res = NULL;
		struct kpm_test_results *rmsg;
		__u32 worker_id, conn_id;

		worker_id = test->req->specs[i].worker_id;
		conn_id = test->req->specs[i].connection_id;
		rmsg = test->results[worker_id - test->min_worker_id];
		if (!rmsg) {
			warnx("No results for worker %d", worker_id);
			goto out;
		}
		for (j = 0; j < rmsg->n_conns; j++) {
			if (rmsg->res[j].connection_id == conn_id) {
				res = &rmsg->res[j];
				break;
			}
		}
		if (!res) {
			warnx("No results for connection %d", conn_id);
			goto out;
		}

		memcpy(&reply->res[i], res, sizeof(*res));
	}

	kpm_dbg("Results sent");
	kpm_send(self->main_sock, &reply->hdr, sz, KPM_MSG_TYPE_TEST_RESULT);

out:
	free(reply);
}

static void
session_wmsg_test(struct session_state *self, struct kpm_header *hdr)
{
	struct kpm_test_results *msg = (void *)hdr;
	__u32 worker_id = msg->res[0].worker_id;
	struct test *test;

	test = session_find_test_by_id(self, msg->test_id);
	if (!test)
		warn("Failed to find test for result");

	test->workers_done++;
	if (test->results[worker_id - test->min_worker_id])
		warnx("Results already reported for worker %d", worker_id);
	test->results[worker_id - test->min_worker_id] = kpm_msg_dup(&msg->hdr);

	kpm_dbg("Results received %d/%d",
		test->workers_done, test->workers_total);

	if (test->workers_done == test->workers_total)
		session_results_assemble(self, test);
}

static void session_handle_worker(struct session_state *self, int fd)
{
	struct kpm_header *hdr;

	hdr = kpm_receive(fd);
	if (!hdr) {
		warnx("worker recv empty");
		self->quit = 1;
		return;
	}
	__kpm_cmd_dbg_start("worker", hdr);

	switch (hdr->type) {
	case KPM_MSG_WORKER_TEST_RESULT:
		session_wmsg_test(self, hdr);
		break;
	default:
		warnx("Unknown worker message type: %d", hdr->type);
		self->quit = 1;
		break;
	}

	__kpm_cmd_dbg_end("worker", hdr);
	free(hdr);
}

static void session_handle_accept_sock(struct session_state *self)
{
	struct sockaddr_in6 sockaddr;
	socklen_t addrlen;
	int cfd;

	__kpm_trace(">>", "accept");

	addrlen = sizeof(sockaddr);
	cfd = accept(self->tcp_sock, (void *)&sockaddr, &addrlen);
	if (cfd < 0)
		warn("Failed to accept conn");
	else
		session_new_conn(self, cfd);
}

static void server_session_loop(int fd)
{
	struct session_state self = { .main_sock = fd, };
	struct epoll_event ev = {}, events[32];
	struct connection *conn, *next;
	unsigned char j;
	int i;

	/* Initialize the data buffer we send/receive, it must match on both
	 * ends, this is how we catch data corruption (ekhm kTLS..).
	 *
	 * We need to do this before initializing TX buffers with the pattern
	 * (e.g., devmem).
	 */
	for (i = 0, j = 0; i < (int)ARRAY_SIZE(patbuf); i++, j++) {
		j = j ?: 1;
		patbuf[i] = j;
	}

	list_head_init(&self.connections);
	list_head_init(&self.workers);
	list_head_init(&self.tests);

	self.epollfd = epoll_create1(0);
	if (self.epollfd < 0)
		err(1, "Failed to create epoll");

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(self.epollfd, EPOLL_CTL_ADD, fd, &ev) < 0)
		err(2, "Failed to init epoll");

	while (!self.quit) {
		int nfds;

		nfds = epoll_wait(self.epollfd, events, ARRAY_SIZE(events), -1);
		if (nfds < 0)
			err(3, "Failed to epoll");

		for (i = 0; i < nfds; i++) {
			struct epoll_event *e = &events[i];

			if (e->data.fd == self.main_sock)
				session_handle_main_sock(&self);
			else if (e->data.fd == self.tcp_sock)
				session_handle_accept_sock(&self);
			else
				session_handle_worker(&self, e->data.fd);
		}
	}

	kpm_dbg("exiting!");

	list_for_each_safe(&self.connections, conn, next, connections) {
		close(conn->fd);
		list_del(&conn->connections);
		free(conn);
	}
	if (self.tcp_sock && self.rx_mode == KPM_RX_MODE_DEVMEM)
		devmem_teardown(&self.devmem);
	if (!self.tcp_sock && self.tx_mode == KPM_TX_MODE_DEVMEM)
		devmem_teardown_tx(&self.devmem);
	if (self.tcp_sock && self.iou && self.rx_mode == KPM_RX_MODE_SOCKET_ZEROCOPY)
		iou_zerocopy_rx_teardown(&self.iou_state);
}

static NORETURN void server_session(int fd)
{
	if (!kpm_xchg_hello(fd, NULL))
		server_session_loop(fd);
	close(fd);
	exit(0);
}

struct server_session *
server_session_spawn(int fd, struct sockaddr_in6 *addr, socklen_t *addrlen)
{
	struct server_session *ses;

	if (get_nprocs() > KPERF_MAX_CPUS) {
		warnx("Too many CPUs in the system: %d, proto has max of %d",
		      get_nprocs(), KPERF_MAX_CPUS);
		return NULL;
	}

	ses = malloc(sizeof(*ses));
	if (!ses) {
		close(fd);
		return NULL;
	}
	memset(ses, 0, sizeof(*ses));

	ses->pid = fork();
	if (ses->pid)
		return ses;

	free(ses);
	server_session(fd);
}
