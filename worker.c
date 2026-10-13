// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>

#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/minmax/minmax.h>

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
	free(conn->rr.sched);
	free(conn);
}

#define NSEC_PER_SEC	1000000000ULL
#define NSEC_PER_MSEC	1000000ULL

static __u64 worker_ns(struct timemono t)
{
	return t.ts.tv_sec * NSEC_PER_SEC + t.ts.tv_nsec;
}

static int
worker_pstat_cmp(unsigned int const *a, unsigned int const *b, void *unused)
{
	return *a < *b ? -1 : *a > *b;
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
	if (conn->rr.log_len)
		data->lat_max = conn->rr.log[conn->rr.log_len - 1];
}

static void
worker_record_lat(struct worker_connection *conn, __u64 start, __u64 nsec)
{
	unsigned int lat;
	int hist_idx;

	/* The first ones run cold, as the test sets up */
	if (start < conn->rr.warmup_end_ns)
		return;

	lat = nsec / KPM_LAT_UNIT_NS > ~0U ? ~0U : nsec / KPM_LAT_UNIT_NS;

	if (conn->spec->arg.rr.timings > 1 &&
	    conn->rr.log_len < conn->rr.log_len_max)
		conn->rr.log[conn->rr.log_len++] = lat;

	hist_idx = 0;
	while (lat) {
		lat >>= 1;
		hist_idx++;
	}
	conn->rr.hist[hist_idx]++;
}

/* == Open loop RR ==
 * Requests go out when due; each response completes the oldest one in
 * flight, its latency counted from when the request was due.
 */

static void worker_rr_start(struct worker_state *self)
{
	struct worker_connection *conn;
	bool open_loop = false;

	list_for_each(&self->connections, conn, connections) {
		if (!worker_rr_open_loop(conn))
			continue;
		conn->rr.start_ns = worker_ns(self->test_start);
		conn->rr.next_ns = conn->rr.start_ns;
		/* Due times of the requests in flight, doubled when full */
		conn->rr.sched_size = 1024;
		conn->rr.sched = calloc(conn->rr.sched_size,
					sizeof(*conn->rr.sched));
		if (!conn->rr.sched) {
			warnx("No memory");
			self->quit = 1;
			return;
		}
		open_loop = true;
	}

	/* Default timer slack is 50us, requests would go out late */
	if (open_loop && prctl(PR_SET_TIMERSLACK, 1UL))
		warn("Failed to set timer slack");
}

static int worker_rr_sched_push(struct worker_connection *conn, __u64 due)
{
	unsigned int n = conn->rr.sched_tail - conn->rr.sched_head;

	if (n == conn->rr.sched_size) {
		unsigned int head = conn->rr.sched_head & (n - 1);
		__u64 *sched;

		/* A power of 2, indexed by masking */
		sched = reallocarray(conn->rr.sched, n * 2, sizeof(*sched));
		if (!sched)
			return -1;
		/* Move the entries which wrapped to the start after the rest */
		memcpy(sched + n, sched, head * sizeof(*sched));
		conn->rr.sched = sched;
		conn->rr.sched_size = n * 2;
		conn->rr.sched_head = head;
		conn->rr.sched_tail = head + n;
	}

	conn->rr.sched[conn->rr.sched_tail++ & (conn->rr.sched_size - 1)] = due;
	return 0;
}

static bool worker_rr_queue_send(struct worker_connection *conn, __u64 len)
{
	bool idle = !conn->to_send;

	conn->to_send += len;
	return idle;
}

/* Send the requests which are due, returns when the next one is */
static __u64 worker_rr_tick(struct worker_state *self, __u64 now)
{
	struct worker_connection *conn, *next;
	__u64 next_ns = ~0ULL;

	list_for_each_safe(&self->connections, conn, next, connections) {
		struct kpm_test_spec *spec = conn->spec;
		__u64 n = 0;

		if (!worker_rr_open_loop(conn))
			continue;

		while (conn->rr.next_ns <= now) {
			if (worker_rr_sched_push(conn, conn->rr.next_ns)) {
				warnx("No memory");
				self->quit = 1;
				return ~0ULL;
			}
			conn->rr.inflight_max = max(conn->rr.inflight_max,
						    conn->rr.sched_tail -
						    conn->rr.sched_head);
			conn->rr.sent++;
			/* Not accumulating the interval, it may be inexact */
			conn->rr.next_ns = conn->rr.start_ns +
				conn->rr.sent * NSEC_PER_SEC / spec->arg.rr.rps;
			n++;
		}

		if (n) {
			if (!conn->to_recv)
				conn->to_recv = spec->arg.rr.resp_size;
			if (worker_rr_queue_send(conn,
						 n * spec->arg.rr.req_size) &&
			    !self->ops->kick_send(self, conn))
				continue; /* killed */
		}

		if (conn->rr.next_ns < next_ns)
			next_ns = conn->rr.next_ns;
	}

	return next_ns;
}

static void
worker_rr_response(struct worker_state *self, struct worker_connection *conn)
{
	__u64 due;

	if (conn->rr.sched_tail == conn->rr.sched_head) {
		warnx("Response without a request");
		return;
	}

	due = conn->rr.sched[conn->rr.sched_head++ &
			     (conn->rr.sched_size - 1)];
	conn->rr.reqs++;
	if (conn->spec->arg.rr.timings)
		worker_record_lat(conn, due, worker_ns(time_mono()) - due);

	if (conn->rr.sched_tail != conn->rr.sched_head)
		conn->to_recv = conn->spec->arg.rr.resp_size;
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

		if (conn->spec->type == KPM_TEST_TYPE_RR) {
			data->reqs = conn->rr.reqs;
			data->rr_sent = conn->rr.sent;
			data->rr_inflight_max = conn->rr.inflight_max;
		}

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
		conn->compl_wait = false;

		/* Drop open loop requests in flight, drain their responses */
		if (worker_rr_open_loop(conn) && self->test->active) {
			__u64 inflight;

			inflight = conn->rr.sched_tail - conn->rr.sched_head;
			if (inflight)
				conn->to_recv += (inflight - 1) *
					conn->spec->arg.rr.resp_size;
		}
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
	struct worker_connection *rr;
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

		if (conn->spec->type == KPM_TEST_TYPE_RR)
			conn->rr.rps = conn->spec->arg.rr.rps;
		if (worker_rr_open_loop(conn)) {
			int one = 1;

			/* Nagle would hold requests behind unacked ones */
			if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY,
				       &one, sizeof(one))) {
				warn("Failed to set TCP_NODELAY");
				self->quit = 1;
			}
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
			/* Open loop requests are sent on a timer */
			if (req->active && conn->spec->arg.rr.rps)
				len = 0;
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
	list_for_each(&self->connections, rr, connections)
		if (rr->spec->type == KPM_TEST_TYPE_RR)
			rr->rr.warmup_end_ns = worker_ns(self->test_start) +
				rr->spec->arg.rr.warmup_ms * NSEC_PER_MSEC;
	memset(&self->prev_loop, 0, sizeof(self->prev_loop));
	if (self->test->active) {
		self->test_len_msec = req->time_sec * 1000;
		worker_rr_start(self);
	}
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
	struct timemono now;

	if (!conn->spec->arg.rr.timings)
		return;

	now = time_mono();
	if (self->prev_loop.ts.tv_sec)
		worker_record_lat(conn, worker_ns(self->prev_loop),
				  worker_ns(now) - worker_ns(self->prev_loop));
	self->prev_loop = now;
}

void
worker_send_finished(struct worker_state *self, struct worker_connection *conn)
{
	if (worker_rr_open_loop(conn))
		return;

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

bool
worker_recv_finished(struct worker_state *self, struct worker_connection *conn)
{
	if (!self->test)
		return false;

	if (conn->spec->type != KPM_TEST_TYPE_RR)
		warnx("Done sending for non-RR test");

	if (worker_rr_open_loop(conn)) {
		if (self->test->active) {
			worker_rr_response(self, conn);
			return false;
		}
		conn->rr.reqs++;
		conn->to_recv = conn->spec->arg.rr.req_size;
		return worker_rr_queue_send(conn, conn->spec->arg.rr.resp_size);
	}

	if (self->test->active)
		conn->to_send =	conn->spec->arg.rr.req_size;
	else
		conn->to_send =	conn->spec->arg.rr.resp_size;
	return true;
}

/* Returns true if the caller has to start sending, nothing being sent */
bool
worker_recv_progress(struct worker_state *self, struct worker_connection *conn,
		     size_t n)
{
	static bool warned;
	bool kick = false;

	while (n) {
		size_t chunk = n < conn->to_recv ? n : conn->to_recv;

		if (!chunk) {
			if (!warned && self->test) {
				warnx("%zu bytes beyond the expected data", n);
				warned = true;
			}
			conn->tot_recv += n;
			break;
		}
		conn->to_recv -= chunk;
		conn->tot_recv += chunk;
		n -= chunk;

		if (!conn->to_recv && worker_recv_finished(self, conn))
			kick = true;
	}

	return kick;
}

/* == Main loop == */
void* worker_main(void* args)
{
	struct worker_opts* opts = args;
	struct worker_state self = {
		.main_sock = opts->fd,
		.opts = *opts,

	};

	free(opts);
	if (self.opts.use_iou)
		worker_iou_init(&self);
	else
		worker_epoll_init(&self);
	list_head_init(&self.connections);

	self.ops->prep(&self);

	while (!self.quit) {
		__s64 nsec = -1;

		/* Check if we should end the test if we initiated */
		if (self.test && self.test->active) {
			__u64 now, end, next;

			now = worker_ns(time_mono());
			end = worker_ns(self.test_start) +
				self.test_len_msec * 1000000ULL;
			if (now >= end) {
				worker_report_test(&self);
			} else {
				next = worker_rr_tick(&self, now);
				if (next > end)
					next = end;
				now = worker_ns(time_mono());
				nsec = next > now ? next - now : 0;
			}
		}

		self.ops->wait(&self, nsec);
	}

	self.ops->exit(&self);
	close(self.main_sock);
	kpm_dbg("exiting!");
	return NULL;
}
