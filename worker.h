// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef WORKER_H
#define WORKER_H 1

#include <linux/tcp.h>

#include <ccan/time/time.h>
#include <ccan/list/list.h>

#include "proto.h"
#include "server.h"

/* Main worker state AKA self */
struct worker_state {
	int main_sock;
	struct worker_opts opts;
	int epollfd;
	unsigned int id;
	int quit;
	int ended;
	struct kpm_test *test;
	struct cpu_stat *cpu_start;
	struct timemono test_start;
	struct timemono prev_loop;
	unsigned int test_len_msec;
	struct list_head connections;
	const struct io_ops *ops;
	void *io_state;
};

struct worker_connection {
	unsigned int id;
	int fd;
	unsigned int read_size;
	unsigned int write_size;
	__u64 to_send;
	__u64 to_send_comp;
	bool compl_wait;
	bool rx_parked;
	__u64 to_recv;
	__u64 tot_sent;
	__u64 tot_recv;
	unsigned char *rxbuf;

	/* zero copy receive */
	size_t rsize;
	void *raddr;
	void *addr;

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

			/* Open loop, spec->arg.rr.rps as spec is freed early */
			unsigned int rps;
			__u64 start_ns;
			__u64 next_ns;
			unsigned int sent;
			unsigned int inflight_max;
			/* FIFO of due times of the requests in flight */
			__u64 *sched;
			unsigned int sched_size;	/* power of 2 */
			unsigned int sched_head;
			unsigned int sched_tail;
		} rr;
	};
	struct list_node connections;
};

struct io_ops {
	void (*prep)(struct worker_state *state);
	/* @nsec < 0 waits until an event */
	void (*wait)(struct worker_state *state, __s64 nsec);
	void (*conn_add)(struct worker_state *state, struct worker_connection *conn);
	void (*conn_close)(struct worker_state *state, struct worker_connection *conn);
	/* Start sending @conn->to_send, nothing being sent; false if killed */
	bool (*kick_send)(struct worker_state *state, struct worker_connection *conn);
	void (*exit)(struct worker_state *state);
};

void worker_handle_proto(struct worker_state *self, struct kpm_header *hdr);
void worker_kill_conn(struct worker_state *self, struct worker_connection *conn);
void worker_send_finished(struct worker_state *self, struct worker_connection *conn);
bool worker_recv_finished(struct worker_state *self, struct worker_connection *conn);
bool worker_recv_progress(struct worker_state *self,
			  struct worker_connection *conn, size_t n);

static inline bool worker_rr_open_loop(struct worker_connection *conn)
{
	return conn->rr.rps;
}

#endif /* WORKER_H */
