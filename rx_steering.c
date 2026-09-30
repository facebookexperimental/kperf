// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/ethtool_netlink.h>
#include <linux/sockios.h>

#include <ccan/err/err.h>

#include <ynl-c/ethtool.h>
#include <ynl-c/ynl.h>

#include "rx_steering.h"

static int steering_rule_loc = -1;

static int ethtool(const char *ifname, void *data)
{
	struct ifreq ifr = {};
	int ret;
	int fd;

	strcat(ifr.ifr_ifrn.ifrn_name, ifname);
	ifr.ifr_ifru.ifru_data = data;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return ret;
}

static void reset_flow_steering(const char *ifname)
{
	struct ethtool_rxnfc del;

	if (steering_rule_loc < 0)
		return;

	del.cmd = ETHTOOL_SRXCLSRLDEL;
	del.fs.location = steering_rule_loc;

	ethtool(ifname, &del);

	steering_rule_loc = -1;
}

static int find_free_rule_loc(const char *ifname, int rule_cnt)
{
	struct ethtool_rxnfc cnt = {};
	struct ethtool_rxnfc *rules;
	int free_loc = 0;

	cnt.cmd = ETHTOOL_GRXCLSRLCNT;
	if (ethtool(ifname, &cnt) < 0)
		return -1;

	rules = calloc(1, sizeof(*rules) + (cnt.rule_cnt * sizeof(__u32)));
	if (!rules)
		return -1;

	rules->cmd = ETHTOOL_GRXCLSRLALL;
	rules->rule_cnt = cnt.rule_cnt;
	if (ethtool(ifname, rules) < 0)
		goto free_rules;

	while (true) {
		bool used = false;
		for (__u32 i = 0; i < rules->rule_cnt; i++)
			if ((unsigned int)free_loc == rules->rule_locs[i]) {
				used = true;
				break;
			}
		if (!used)
			break;
		free_loc++;
	}

	free(rules);
	return free_loc;

free_rules:
	free(rules);
	return -1;
}

static int add_steering_rule(struct sockaddr_in6 *server_sin,
			     const char *ifname, int rss_context)
{
	struct ethtool_rxnfc add = {};
	struct ethtool_rxnfc cnt = {};
	int ret;

	add.cmd = ETHTOOL_SRXCLSRLINS;
	add.rss_context = rss_context;

	if (IN6_IS_ADDR_V4MAPPED(&server_sin->sin6_addr)) {
		add.fs.flow_type = TCP_V4_FLOW;
                memcpy(&add.fs.h_u.tcp_ip4_spec.ip4dst,
                       &server_sin->sin6_addr.s6_addr32[3], 4);
                memcpy(&add.fs.h_u.tcp_ip4_spec.pdst,
		       &server_sin->sin6_port, 2);

		add.fs.m_u.tcp_ip4_spec.ip4dst = 0xffffffff;
		add.fs.m_u.tcp_ip4_spec.pdst = 0xffff;
	} else {
		add.fs.flow_type = TCP_V6_FLOW;
                memcpy(add.fs.h_u.tcp_ip6_spec.ip6dst, &server_sin->sin6_addr,
                       16);
                memcpy(&add.fs.h_u.tcp_ip6_spec.pdst, &server_sin->sin6_port,
                       2);

                add.fs.m_u.tcp_ip6_spec.ip6dst[0] = 0xffffffff;
		add.fs.m_u.tcp_ip6_spec.ip6dst[1] = 0xffffffff;
		add.fs.m_u.tcp_ip6_spec.ip6dst[2] = 0xffffffff;
		add.fs.m_u.tcp_ip6_spec.ip6dst[3] = 0xffffffff;
		add.fs.m_u.tcp_ip6_spec.pdst = 0xffff;
	}

	add.fs.flow_type |= FLOW_RSS;

	cnt.cmd = ETHTOOL_GRXCLSRLCNT;
	ret = ethtool(ifname, &cnt);
	if (ret)
		return ret;

	if (cnt.data & RX_CLS_LOC_SPECIAL)
		add.fs.location = RX_CLS_LOC_ANY;
	else if (cnt.rule_cnt) {
		ret = find_free_rule_loc(ifname, cnt.rule_cnt);
		if (ret < 0) {
			warnx("Failed to find free steering rule loc");
			return -1;
		}
		add.fs.location = ret;
	}

	ret = ethtool(ifname, &add);
	if (ret)
		return ret;

	steering_rule_loc = add.fs.location;

	return 0;
}

static int rss_context_delete(char *ifname, int rss_context)
{
	struct ethtool_rxfh set = {};

	set.cmd = ETHTOOL_SRSSH;
	set.rss_context = rss_context;
	set.indir_size = 0;

	if (ethtool(ifname, &set) < 0) {
		warn("ethtool failed to delete RSS context %u", rss_context);
		return -1;
	}

	return 0;
}

static int rss_context_equal(char *ifname, int start_queue, int num_queues,
			     struct sockaddr_in6 *addr)
{
	struct ethtool_rxfh get = {};
	struct ethtool_rxfh *set;
	__u32 indir_bytes;
	int rss_context;
	int queue;
	int ret;

	get.cmd = ETHTOOL_GRSSH;
	if (ethtool(ifname, &get) < 0) {
		warn("ethtool failed to get RSS context");
		return -1;
	}

	indir_bytes = get.indir_size * sizeof(get.rss_config[0]);

	set = calloc(1, sizeof(*set) + indir_bytes);
	if (!set) {
		warn("failed to allocate memory");
		return -1;
	}

	set->cmd = ETHTOOL_SRSSH;
	set->rss_context = ETH_RXFH_CONTEXT_ALLOC;
	set->indir_size = get.indir_size;

	queue = start_queue;
	for (__u32 i = 0; i < get.indir_size; i++) {
		set->rss_config[i] = queue++;
		if (queue >= start_queue + num_queues)
			queue = start_queue;
	}

	if (ethtool(ifname, set) < 0) {
		warn("ethtool failed to create RSS context");
		ret = -1;
		goto free_set;
	}

	rss_context = set->rss_context;

	if (add_steering_rule(addr, ifname, rss_context) < 0) {
		warn("Failed to add rule to RSS context");
		ret = -1;
		goto delete_context;
	}

	free(set);

	return rss_context;

delete_context:
	rss_context_delete(ifname, rss_context);

free_set:
	free(set);

	return ret;
}

static int rss_equal(const char *ifname, int max_queue)
{
	struct ethtool_rxfh_indir get = {};
	struct ethtool_rxfh_indir *set;
	int queue = 0;
	int ret;

	get.cmd = ETHTOOL_GRXFHINDIR;
	if (ethtool(ifname, &get) < 0)
		return -1;

	set = malloc(sizeof(*set) + get.size * sizeof(__u32));
	if (!set)
		return -1;

	for (__u32 i = 0; i < get.size; i++) {
		set->ring_index[i] = queue++;
		if (queue >= max_queue)
			queue = 0;
	}

	set->cmd = ETHTOOL_SRXFHINDIR;
	set->size = get.size;
	ret = ethtool(ifname, set);

	free(set);
	return ret;
}

static int rxq_num(int ifindex)
{
	struct ethtool_channels_get_req *req;
	struct ethtool_channels_get_rsp *rsp;
	struct ynl_error yerr;
	struct ynl_sock *ys;
	int num = -1;

	ys = ynl_sock_create(&ynl_ethtool_family, &yerr);
	if (!ys) {
		warnx("Failed to setup YNL socket: %s", yerr.msg);
		return -1;
	}

	req = ethtool_channels_get_req_alloc();
	ethtool_channels_get_req_set_header_dev_index(req, ifindex);
	rsp = ethtool_channels_get(ys, req);
	if (rsp)
		num = rsp->rx_count + rsp->combined_count;
	else
		warnx("ethtool_channels_get: %s", ys->err.msg);
	ethtool_channels_get_req_free(req);
	ethtool_channels_get_rsp_free(rsp);
	ynl_sock_destroy(ys);

	return num;
}

static void inet_to_inet6(struct sockaddr *addr, struct sockaddr_in6 *out)
{
	out->sin6_addr.s6_addr32[3] = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	out->sin6_addr.s6_addr32[0] = 0;
	out->sin6_addr.s6_addr32[1] = 0;
	out->sin6_addr.s6_addr16[4] = 0;
	out->sin6_addr.s6_addr16[5] = 0xffff;
	out->sin6_family = AF_INET6;
}

int rx_steering_find_iface(struct sockaddr_in6 *addr, char ifname[IFNAMSIZ])
{
	struct ifaddrs *ifaddr, *ifa;
	struct sockaddr_in6 tmp;

	if (getifaddrs(&ifaddr) < 0)
		return -errno;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
			inet_to_inet6(ifa->ifa_addr, &tmp);
		else if (ifa->ifa_addr->sa_family == AF_INET6)
			memcpy(&tmp, ifa->ifa_addr, sizeof(tmp));
		else
			continue;

		if (!memcmp(&tmp.sin6_addr, &addr->sin6_addr,
			    sizeof(tmp.sin6_addr))) {
			strncpy(ifname, ifa->ifa_name, IFNAMSIZ - 1);
			freeifaddrs(ifaddr);
			return if_nametoindex(ifname);
		}
        }

	freeifaddrs(ifaddr);
	return -ENODEV;
}

int reserve_queues(int fd, int num_queues, char out_ifname[IFNAMSIZ],
		   int *out_ifindex, int *out_queue_id, int *out_rss_context)
{
	struct sockaddr_in6 addr;
	char ifname[IFNAMSIZ];
	int max_kernel_queue;
	socklen_t optlen;
	int rss_context;
	int ifindex;
	int ret = 0;
	int rxqn;

	if (num_queues <= 0) {
		warnx("Invalid number of RX queues: %u", num_queues);
		return -1;
	}

	optlen = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *)&addr, &optlen) < 0) {
		warn("Failed to query socket address");
		return -1;
	}

	if (addr.sin6_family == AF_INET)
		inet_to_inet6((void *)&addr, &addr);

	ifindex = rx_steering_find_iface(&addr, ifname);
	if (ifindex < 0) {
		warnx("Failed to resolve ifindex: %s", strerror(-ifindex));
		return -1;
	}

	rxqn = rxq_num(ifindex);
	if (rxqn < 2) {
		warnx("Invalid number of queues: %d", rxqn);
		return -1;
	}

	if (num_queues >= rxqn - 1) {
		warnx("Invalid number of RX queues (%u) requested (max: %u)",
		      num_queues, rxqn - 1);
		return -1;
	}

	max_kernel_queue = rxqn - num_queues;

	reset_flow_steering(ifname);
	if (rss_equal(ifname, max_kernel_queue)) {
		warnx("Failed to setup RSS");
		return -1;
	}

	rss_context = rss_context_equal(ifname, max_kernel_queue,
					num_queues, &addr);
	if (rss_context < 0) {
		warnx("Failed to setup RSS context");
		ret = -1;
		goto undo_rss;
	}

	memcpy(out_ifname, ifname, IFNAMSIZ);
	*out_ifindex = ifindex;
	*out_queue_id = max_kernel_queue;
	*out_rss_context = rss_context;

	return ret;

undo_rss:
	rss_equal(ifname, rxqn);

	return ret;
}

void unreserve_queues(char *ifname, int rss_context)
{
	int ifindex;
	int rxqn;

	reset_flow_steering(ifname);
	rss_context_delete(ifname, rss_context);
	ifindex = if_nametoindex(ifname);
	if (ifindex > 0) {
		rxqn = rxq_num(ifindex);
		if (rxqn > 0)
			rss_equal(ifname, rxqn);
	}
}

int rx_steering_setup(struct rx_steering *steering, int fd, int num_queues)
{
	int ret;

	ret = reserve_queues(fd, num_queues, steering->ifname,
			     &steering->ifindex, &steering->queue_id,
			     &steering->rss_context);
	if (ret)
		return ret;

	steering->configured = true;
	return 0;
}

void rx_steering_teardown(struct rx_steering *steering)
{
	if (!steering->configured)
		return;

	unreserve_queues(steering->ifname, steering->rss_context);
	steering->configured = false;
}
