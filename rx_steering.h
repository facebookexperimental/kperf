/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef RX_STEERING_H
#define RX_STEERING_H 1

#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>

struct rx_steering {
	char ifname[IFNAMSIZ];
	int ifindex;
	int queue_id;
	int rss_context;
	bool configured;
};

int rx_steering_find_iface(struct sockaddr_in6 *addr,
			   char ifname[IFNAMSIZ]);
int rx_steering_setup(struct rx_steering *steering, int fd, int num_queues);
void rx_steering_teardown(struct rx_steering *steering);

#endif /* RX_STEERING_H */
