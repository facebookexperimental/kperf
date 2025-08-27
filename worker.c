// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>

#include "worker.h"
#include "cpu_stat.h"
#include "tcp.h"
#include "proto_dbg.h"
#include "server.h"
#include "tcp.h"
#include "iou.h"
#include "epoll.h"

unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

void
worker_kill_conn(struct worker_state *self, struct worker_connection *conn)
{
	self->ops->conn_close(self, conn);
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
worker_report_pstats(struct worker_state *self, struct worker_connection *conn,
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
	struct worker_connection *conn;
	struct cpu_stat *cpu, *cpu_pct;
	struct kpm_test_results *res;
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

	if (self->test) {
		warn("Already running a test");
		self->quit = 1;
		return;
	}

	kpm_dbg("start test %s", req->active ? "act" : "psv");

	self->test = malloc(hdr->len);
	memcpy(self->test, req, hdr->len);

	for (i = 0; i < req->n_conns; i++) {
		struct worker_connection *conn;
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

		self->ops->conn_add(self, conn);
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
	struct worker_connection *conn, *next;

	if (self->test)
		worker_report_test(self);

	free(self->cpu_start);
	self->cpu_start = NULL;
	list_for_each_safe(&self->connections, conn, next, connections)
		worker_kill_conn(self, conn);
	self->ended = 1;
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

void worker_handle_proto(struct worker_state *self, struct kpm_header *hdr)
{
	int i;

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
}

/* == Worker I/O handling == */

static void
worker_record_rr_time(struct worker_state *self, struct worker_connection *conn)
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

void
worker_send_finished(struct worker_state *self, struct worker_connection *conn)
{
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

void
worker_recv_finished(struct worker_state *self, struct worker_connection *conn)
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

/* == Main loop == */

void NORETURN pworker_main(int fd, struct worker_opts opts)
{
	struct worker_state self = {
		.main_sock = fd,
		.opts = opts,
	};

	if (opts.use_iou)
		worker_iou_init(&self);
	else
		worker_epoll_init(&self);

	list_head_init(&self.connections);

	self.ops->prep(&self);

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

		self.ops->wait(&self, msec);
	}

	self.ops->exit(&self);
	kpm_dbg("exiting!");
	exit(0);
}
