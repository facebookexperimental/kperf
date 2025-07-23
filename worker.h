// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef WORKER_H
#define WORKER_H 1

#include <ccan/time/time.h>
#include <ccan/list/list.h>

#include "proto.h"
#include "server.h"

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
	const struct worker_ops *ops;
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

struct worker_ops {
	void (*prep)(struct worker_state *state);
	void (*wait)(struct worker_state *state, int msec);
	void (*conn_add)(struct worker_state *state, struct connection *conn);
	void (*conn_close)(struct worker_state *state, struct connection *conn);
};

#endif /* WORKER_H */
