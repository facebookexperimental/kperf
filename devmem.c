// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/dma-buf.h>
#include <linux/ethtool_netlink.h>
#include <linux/sockios.h>
#include <linux/udmabuf.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>

#include <ynl-c/ethtool.h>
#include <ynl-c/netdev.h>

#include "server.h"

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

static int ethtool(const char *ifname, void *data)
{
	struct ifreq ifr = {};
	int ret;

	strcat(ifr.ifr_ifrn.ifrn_name, ifname);
	ifr.ifr_ifru.ifru_data = data;

	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return ret;
}

static void reset_flow_steering(const char *ifname)
{
	struct ethtool_rxnfc cnt = {};
	struct ethtool_rxnfc *rules;

	cnt.cmd = ETHTOOL_GRXCLSRLCNT;
	if (ethtool(ifname, &cnt) < 0)
		return;

	rules = calloc(1, sizeof(*rules) + (cnt.rule_cnt * sizeof(__u32)));
	if (!rules)
		return;

	rules->cmd = ETHTOOL_GRXCLSRLALL;
	rules->rule_cnt = cnt.rule_cnt;
	if (ethtool(ifname, rules) < 0)
		goto free_rules;

	for (__u32 i = 0; i < rules->rule_cnt; i++) {
		struct ethtool_rxnfc del;

		del.cmd = ETHTOOL_SRXCLSRLDEL;
		del.fs.location = rules->rule_locs[i];

		ethtool(ifname, &del);
	}

free_rules:
	free(rules);
}

static int add_steering_rule(struct sockaddr_in6 *server_sin,
			     const char *ifname, int rss_context)
{
	struct ethtool_rxnfc add = {};

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

	return ethtool(ifname, &add);
}

static int rss_context_delete(struct session_state_devmem *devmem)
{
	struct ethtool_rxfh set = {};

	if (!devmem->rss_context)
		return 0;

	set.cmd = ETHTOOL_SRSSH;
	set.rss_context = devmem->rss_context;
	set.indir_size = 0;

	if (ethtool(devmem->ifname, &set) < 0) {
		warn("ethtool failed to delete RSS context %u", devmem->rss_context);
		return -1;
	}

	devmem->rss_context = 0;

	return 0;
}

static int rss_context_equal(struct session_state_devmem *devmem, int start_queue,
			     int num_queues, struct sockaddr_in6 *addr)
{
	struct ethtool_rxfh get = {};
	struct ethtool_rxfh *set;
	__u32 indir_bytes;
	int queue;
	int ret;

	get.cmd = ETHTOOL_GRSSH;
	if (ethtool(devmem->ifname, &get) < 0) {
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

	if (ethtool(devmem->ifname, set) < 0) {
		warn("ethtool failed to create RSS context");
		ret = -1;
		goto free_set;
	}

	devmem->rss_context = set->rss_context;

	if (add_steering_rule(addr, devmem->ifname, devmem->rss_context) < 0) {
		warn("Failed to add rule to RSS context");
		ret = -1;
		goto delete_context;
	}

	free(set);

	return 0;

delete_context:
	rss_context_delete(devmem);

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

static int bind_rx_queue(unsigned int ifindex, unsigned int dmabuf_fd,
			 struct netdev_queue_id *queues,
			 unsigned int n_queue_index, struct ynl_sock *ys)
{
	struct netdev_bind_rx_req *req;
	struct netdev_bind_rx_rsp *rsp;
	int ret = -1;

	req = netdev_bind_rx_req_alloc();
	if (!req)
		return -1;

	netdev_bind_rx_req_set_ifindex(req, ifindex);
	netdev_bind_rx_req_set_fd(req, dmabuf_fd);
	__netdev_bind_rx_req_set_queues(req, queues, n_queue_index);

	rsp = netdev_bind_rx(ys, req);
	if (!rsp) {
		warnx("netdev_bind_rx: %s", ys->err.msg);
		goto out;
	}

	if (!rsp->_present.id) {
		warnx("id not present");
		goto out;
	}

	ret = rsp->id;

out:
	if (req)
		netdev_bind_rx_req_free(req);
	if (rsp)
		netdev_bind_rx_rsp_free(rsp);

	return ret;
}

#define UDMABUF_LIMIT_PATH "/sys/module/udmabuf/parameters/size_limit_mb"

static int udmabuf_check_size(size_t size_mb)
{
	size_t limit_mb = 0;
	int ret = 0;
	FILE *f;

	f = fopen(UDMABUF_LIMIT_PATH, "r");
	if (f) {
		fscanf(f, "%lu", &limit_mb);
		if (size_mb > limit_mb) {
                  warnx(
                      "udmabuf size limit is too small (%lu > %lu), update %s",
                      size_mb, limit_mb, UDMABUF_LIMIT_PATH);
                  ret = -EINVAL;
		}
		fclose(f);
	}

	return ret;
}

static int udmabuf_alloc(struct memory_buffer *mem, const char *name, size_t size_mb)
{
	struct udmabuf_create create;
	int ret;

	ret = udmabuf_check_size(size_mb);
	if (ret < 0)
		return ret;

	mem->devfd = open("/dev/udmabuf", O_RDWR);
	if (mem->devfd < 0)
		return -errno;

	mem->memfd = memfd_create(name, MFD_ALLOW_SEALING);
	if (mem->memfd < 0) {
		ret = -errno;
		goto close_devfd;
	}

	ret = fcntl(mem->memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0) {
		ret = -errno;
		goto close_memfd;
	}

	ret = ftruncate(mem->memfd, size_mb * 1024 * 1024);
	if (ret < 0) {
		ret = -errno;
		goto close_memfd;
	}

	memset(&create, 0, sizeof(create));

	create.memfd = mem->memfd;
	create.offset = 0;
	create.size = size_mb * 1024 * 1024;

        mem->fd = ioctl(mem->devfd, UDMABUF_CREATE, &create);
        if (mem->fd < 0) {
		ret = -errno;
		goto close_memfd;
	}

	mem->size = size_mb * 1024 * 1024;
	mem->buf_mem = mmap(NULL, mem->size, PROT_READ | PROT_WRITE,
				  MAP_SHARED, mem->fd, 0);

	if (mem->buf_mem == MAP_FAILED) {
		ret = -errno;
		goto close_dmabuf_fd;
	}

	return 0;

close_dmabuf_fd:
	close(mem->fd);
close_memfd:
	close(mem->memfd);
close_devfd:
	close(mem->devfd);

	return ret;
}

static void udmabuf_free(struct memory_buffer *mem)
{
	if (mem->buf_mem) {
		close(mem->fd);
		close(mem->memfd);
		close(mem->devfd);
		munmap(mem->buf_mem, mem->size);
	}
}

static void inet_to_inet6(struct sockaddr *addr, struct sockaddr_in6 *out)
{
	out->sin6_addr.s6_addr32[3] = ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr32[0];
	out->sin6_addr.s6_addr32[0] = 0;
	out->sin6_addr.s6_addr32[1] = 0;
	out->sin6_addr.s6_addr16[4] = 0;
	out->sin6_addr.s6_addr16[5] = 0xffff;
	out->sin6_family = AF_INET6;
}

static int find_iface(struct sockaddr_in6 *addr, char ifname[IFNAMSIZ])
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

int devmem_setup(struct session_state_devmem *devmem, int fd,
		 size_t udmabuf_size_mb, int num_queues)
{
	struct netdev_queue_id *queues;
	char ifname[IFNAMSIZ] = {};
	struct sockaddr_in6 addr;
	struct ynl_error yerr;
	int max_kernel_queue;
	socklen_t optlen;
	int ifindex;
	int rxqn;
	int ret;

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

	ifindex = find_iface(&addr, ifname);
	if (ifindex < 0) {
		warnx("Failed to resolve ifindex: %s", strerror(-ifindex));
		return -1;
	}

	devmem->ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!devmem->ys) {
		warnx("Failed to setup YNL socket: %s", yerr.msg);
		return -1;
	}

	rxqn = rxq_num(ifindex);
	if (rxqn < 2) {
		warnx("Invalid number of queues: %d", rxqn);
		ret = -1;
		goto sock_destroy;
	}

	ret = udmabuf_alloc(&devmem->mem, "udmabuf-test-rx", udmabuf_size_mb);
	if (ret < 0) {
		warnx("Failed to allocate udmabuf: %s", strerror(-ret));
		ret = -1;
		goto sock_destroy;
	}

	if (num_queues >= rxqn - 1) {
		warnx("Invalid number of RX queues (%u) requested (max: %u)",
		      num_queues, rxqn - 1);
		ret = -1;
		goto free_udmabuf;
	}

	max_kernel_queue = rxqn - num_queues;

	reset_flow_steering(ifname);
	if (rss_equal(ifname, max_kernel_queue)) {
		warnx("Failed to setup RSS");
		ret = -1;
		goto free_udmabuf;
	}

	memcpy(devmem->ifname, ifname, IFNAMSIZ);

	if (rss_context_equal(devmem, max_kernel_queue, num_queues, &addr) < 0) {
		warnx("Failed to setup RSS context");
		ret = -1;
		goto undo_rss;
	}

	queues = calloc(num_queues, sizeof(*queues));
	if (!queues) {
		warn("Failed to allocate memory for queues");
		ret = -1;
		goto undo_rss_context;
	}

	for (int i = 0; i < num_queues; i++) {
		queues[i]._present.type = 1;
		queues[i]._present.id = 1;
		queues[i].type = NETDEV_QUEUE_TYPE_RX;
		queues[i].id = max_kernel_queue + i;
	}

        devmem->mem.dmabuf_id = bind_rx_queue(ifindex, devmem->mem.fd, queues,
                                          num_queues, devmem->ys);
        if (devmem->mem.dmabuf_id < 0) {
		warnx("Failed to bind RX queue");
		ret = -1;
		goto free_queues;
	}

	return 0;

free_queues:
	free(queues);
undo_rss_context:
	rss_context_delete(devmem);
undo_rss:
	rss_equal(ifname, rxqn);
free_udmabuf:
	udmabuf_free(&devmem->mem);
sock_destroy:
	ynl_sock_destroy(devmem->ys);
	devmem->ys = NULL;

	return ret;
}

int devmem_teardown(struct session_state_devmem *devmem)
{
	int rxqn;
	int ifindex;

	reset_flow_steering(devmem->ifname);
	rss_context_delete(devmem);
        ifindex = if_nametoindex(devmem->ifname);
	if (ifindex > 0) {
		rxqn = rxq_num(ifindex);
		if (rxqn > 0)
			rss_equal(devmem->ifname, rxqn);
	}
	if (devmem->ys)
		ynl_sock_destroy(devmem->ys);
	udmabuf_free(&devmem->mem);
	return 0;
}

int devmem_release_tokens(int fd, struct connection_devmem *conn)
{
	int ret;

	if (!conn->rxtok_len)
		return 0;

	ret = setsockopt(fd, SOL_SOCKET, SO_DEVMEM_DONTNEED, &conn->rxtok[0],
		  sizeof(struct dmabuf_token) * conn->rxtok_len);

	if (ret >= 0 && ret != conn->rxtok_len)
		warnx("requested to release %d token, got %d", conn->rxtok_len,
		      ret);

        conn->rxtok_len = 0;

	return ret;
}

static int devmem_validate_token(struct memory_buffer *mem,
				 struct cmsghdr *cm, int rep, __u64 *tot_recv)
{
	struct dmabuf_cmsg *dmabuf_cmsg = (struct dmabuf_cmsg *)CMSG_DATA(cm);
	struct dma_buf_sync sync = {};
	size_t start;
	void *pat;
	int ret;

	start = *tot_recv % PATTERN_PERIOD;
	if (start + dmabuf_cmsg->frag_size > ARRAY_SIZE(patbuf)) {
		warnx("dmabuf fragment size too big");
		return -1;
	}

	sync.flags = DMA_BUF_SYNC_START;
	ioctl(mem->fd, DMA_BUF_IOCTL_SYNC, &sync);

	pat = &patbuf[start];
	ret = memcmp(pat, mem->buf_mem + dmabuf_cmsg->frag_offset, dmabuf_cmsg->frag_size);

	sync.flags = DMA_BUF_SYNC_END;
	ioctl(mem->fd, DMA_BUF_IOCTL_SYNC, &sync);

	if (ret) {
		warnx("Data corruption %d %d %d %lld %lld %d",
		      *(char *)mem->buf_mem, *(char *)pat, dmabuf_cmsg->frag_size,
		      *tot_recv % PATTERN_PERIOD,
		      *tot_recv, rep);
		return -1;
	}

	*tot_recv += dmabuf_cmsg->frag_size;

	return 0;
}

static int devmem_handle_token(int fd, struct connection_devmem *conn,
			       struct cmsghdr *cm)
{
	struct dmabuf_cmsg *dmabuf_cmsg = (struct dmabuf_cmsg *)CMSG_DATA(cm);
	struct dmabuf_token *token;

	if (cm->cmsg_type == SO_DEVMEM_LINEAR) {
		warnx("received linear chunk, flow steering error?");
		return -EFAULT;
	}

	if (conn->rxtok_len == ARRAY_SIZE(conn->rxtok)) {
		int ret;

		ret = devmem_release_tokens(fd, conn);
		if (ret < 0)
			return ret;
	}

	token = &conn->rxtok[conn->rxtok_len++];
	token->token_start = dmabuf_cmsg->frag_token;
	token->token_count = 1;

	return 0;
}

ssize_t devmem_recv(int fd, struct connection_devmem *conn,
		    unsigned char *rxbuf, size_t chunk,
		    struct memory_buffer *mem, int rep, __u64 tot_recv,
		    bool validate)
{
	struct msghdr msg = {};
	struct iovec iov = {
		.iov_base = NULL,
		.iov_len = chunk,
	};
	struct cmsghdr *cm;
	int tokens = 0;
	ssize_t n;
	int ret;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = conn->ctrl_data;
	msg.msg_controllen = sizeof(conn->ctrl_data);
	n = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_SOCK_DEVMEM);
	if (n < 0)
		return n;

	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level != SOL_SOCKET ||
		    (cm->cmsg_type != SO_DEVMEM_DMABUF &&
		     cm->cmsg_type != SO_DEVMEM_LINEAR))
			continue;

		ret = devmem_handle_token(fd, conn, cm);
		if (ret < 0)
			return ret;

		if (validate) {
			ret = devmem_validate_token(mem, cm, rep, &tot_recv);
			if (ret < 0)
				return ret;
		}

		tokens++;
	}

	if (!tokens) {
		warnx("devmem recvmsg returned no tokens");
		errno = -EFAULT;
		return -1;
	}

	return n;
}
