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
#include <sys/wait.h>

#include <linux/dma-buf.h>
#include <linux/ethtool_netlink.h>
#include <linux/sockios.h>
#include <linux/udmabuf.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>

#include <ynl-c/ethtool.h>
#include <ynl-c/netdev.h>

#include "server.h"
#include "proto_dbg.h"

#ifdef USE_CUDA
#include <cuda.h>
#include <cuda_runtime.h>

#ifdef CU_MEM_RANGE_FLAG_DMA_BUF_MAPPING_TYPE_PCIE
#define CUDA_FLAGS CU_MEM_RANGE_FLAG_DMA_BUF_MAPPING_TYPE_PCIE
#else
#define CUDA_FLAGS 0
#endif
#endif

enum cuda_opt_type {
	CUDA_OPT_TYPE_SETUP_RX,
	CUDA_OPT_TYPE_SETUP_TX,
	CUDA_OPT_TYPE_TEARDOWN_RX,
	CUDA_OPT_TYPE_TEARDOWN_TX,
};

struct cuda_ctx_worker_opts {
	enum cuda_opt_type type;
	int tcp_fd;
	size_t dmabuf_size_mb;
	int num_queues;
	struct pci_dev *dev;
	struct sockaddr_in6 *addr;
	int kpm_fd;
	pid_t pid;
};

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

static int steering_rule_loc = -1;

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

static int bind_tx_queue(unsigned int ifindex, unsigned int dmabuf_fd,
			 struct ynl_sock *ys)
{
	struct netdev_bind_tx_req *req = NULL;
	struct netdev_bind_tx_rsp *rsp = NULL;
	int ret;

	req = netdev_bind_tx_req_alloc();
	if (!req) {
		warnx("netdev_bind_tx_req_alloc() failed");
		return -1;
	}
	netdev_bind_tx_req_set_ifindex(req, ifindex);
	netdev_bind_tx_req_set_fd(req, dmabuf_fd);

	rsp = netdev_bind_tx(ys, req);
	if (!rsp) {
		warnx("netdev_bind_tx");
		ret = -1;
		goto free_req;
	}

	if (!rsp->_present.id) {
		warnx("id not present");
		ret = -1;
		goto free_rsp;
	}

	ret = rsp->id;
	netdev_bind_tx_req_free(req);
	netdev_bind_tx_rsp_free(rsp);

	return ret;

free_rsp:
	netdev_bind_tx_rsp_free(rsp);
free_req:
	netdev_bind_tx_req_free(req);
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

static struct memory_buffer *udmabuf_alloc(size_t size)
{
	struct udmabuf_create create;
	struct memory_buffer *mem;
	int ret;

	mem = calloc(1, sizeof(*mem));
	if (!mem)
		return NULL;

	ret = udmabuf_check_size(size / 1024 / 1024);
	if (ret < 0) {
		warnx("Failed: udmabuf_check_size(), ret=%d", ret);
		goto free_mem;
	}

	mem->devfd = open("/dev/udmabuf", O_RDWR);
	if (mem->devfd < 0) {
		warn("Failed to open /dev/udmabuf");
		goto free_mem;
	}

	mem->memfd = memfd_create("udmabuf-test", MFD_ALLOW_SEALING);
	if (mem->memfd < 0) {
		warn("memfd_create() failed");
		goto close_devfd;
	}

	ret = fcntl(mem->memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0) {
		warn("fcntl() failed");
		goto close_memfd;
	}

	ret = ftruncate(mem->memfd, size);
	if (ret < 0) {
		warn("ftruncate() failed");
		goto close_memfd;
	}

	memset(&create, 0, sizeof(create));

	create.memfd = mem->memfd;
	create.offset = 0;
	create.size = size;

        mem->fd = ioctl(mem->devfd, UDMABUF_CREATE, &create);
        if (mem->fd < 0) {
		warn("ioctl(mem->devfd) failed");
		goto close_memfd;
	}

	mem->size = size;
	mem->provider = MEMORY_PROVIDER_HOST;
	mem->buf_mem = mmap(NULL, mem->size, PROT_READ | PROT_WRITE,
				  MAP_SHARED, mem->fd, 0);

	if (mem->buf_mem == MAP_FAILED) {
		ret = -errno;
		goto close_dmabuf_fd;
	}

	return mem;

close_dmabuf_fd:
	close(mem->fd);
close_memfd:
	close(mem->memfd);
close_devfd:
	close(mem->devfd);
free_mem:
	free(mem);
	return NULL;
}

static void udmabuf_free(struct memory_buffer *mem)
{
	if (mem->buf_mem) {
		close(mem->fd);
		close(mem->memfd);
		close(mem->devfd);
		munmap(mem->buf_mem, mem->size);
	}
	free(mem);
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

void udmabuf_memcpy_to_device(struct memory_buffer *dst, size_t off,
			      void *src, int n)
{
	struct dma_buf_sync sync = {};

	sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_WRITE;
	ioctl(dst->fd, DMA_BUF_IOCTL_SYNC, &sync);

	memcpy(dst->buf_mem + off, src, n);

	sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE;
	ioctl(dst->fd, DMA_BUF_IOCTL_SYNC, &sync);
}

static struct memory_provider udmabuf_memory_provider = {
	.alloc = udmabuf_alloc,
	.free = udmabuf_free,
	.memcpy_to_device = udmabuf_memcpy_to_device,
};

static struct memory_provider *rxmp;
static struct memory_provider *txmp;

#ifdef USE_CUDA

 /* Length of str: 'XXXX:XX:XX' */
#define MAX_BUS_ID_LEN 11

static int cuda_find_device(__u16 domain, __u8 bus, __u8 device)
{
	char bus_id[MAX_BUS_ID_LEN];
	int devnum;
	int ret;

	ret = snprintf(bus_id, MAX_BUS_ID_LEN, "%hx:%hhx:%hhx", domain, bus, device);
	if (ret < 0)
		return -EINVAL;

	ret = cudaDeviceGetByPCIBusId(&devnum, bus_id);
	if (ret != cudaSuccess) {
		warnx("No CUDA device found %s", bus_id);
		return -EINVAL;
	}

	return devnum;
}

static int cuda_dev_init(struct pci_dev *dev)
{
	struct cudaDeviceProp deviceProp;
	CUdevice cuda_dev;
	int devnum;
	int ret;
	int ok;

	ret = cuInit(0);
	if (ret != CUDA_SUCCESS)
		return -1;

	/* If the user did not specify a device, select any device */
	if (dev->domain == DEVICE_DOMAIN_ANY && dev->bus == DEVICE_BUS_ANY && dev->device == DEVICE_DEVICE_ANY) {
		devnum = 0;
	} else {
		devnum = cuda_find_device(dev->domain, dev->bus, dev->device);
		if (devnum < 0)
			return -1;
	}

	ret = cuDeviceGet(&cuda_dev, devnum);
	if (ret != CUDA_SUCCESS)
		return -1;

	ok = 0;
	ret = cuDeviceGetAttribute(&ok, CU_DEVICE_ATTRIBUTE_DMA_BUF_SUPPORTED,
				   cuda_dev);
	if (ret != CUDA_SUCCESS || !ok) {
		if (!ok)
			warnx("CUDA device does not support dmabuf");
		return -1;
	}

	ret = cudaSetDevice(devnum);
	if (ret != cudaSuccess) {
		warn("cudaSetDevice() failed with error %d", ret);
		return -1;
	}

	if (verbose >= 4)
		fprintf(stderr, "cuda: tid %d selecting device %d (%s)\n",
			getpid(), devnum, deviceProp.name);

	return 0;
}

static struct memory_buffer *cuda_alloc(size_t size)
{
	struct memory_buffer *mem;
	size_t page_size;
	int ret;

	page_size = sysconf(_SC_PAGESIZE);
	if (size % page_size) {
		warnx("cuda memory size not aligned, size 0x%lx", size);
		return NULL;
	}

	mem = calloc(1, sizeof(*mem));
	if (!mem)
		return NULL;
	memset(mem, 0, sizeof(*mem));
	mem->size = size;
	mem->provider = MEMORY_PROVIDER_CUDA;

	ret = cudaMalloc((void *)&mem->buf_mem, size);
	if (ret != CUDA_SUCCESS)
		goto free_mem;

	ret = cudaIpcGetMemHandle(&mem->cuda.handle, mem->buf_mem);
	if (ret != CUDA_SUCCESS)
		goto free_cuda;

	ret = cuMemGetHandleForAddressRange((void *)&mem->fd, ((CUdeviceptr)mem->buf_mem),
					    size, CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD,
					    CUDA_FLAGS);
	if (ret != CUDA_SUCCESS)
		goto free_cuda;

	return mem;

free_cuda:
	if (cudaFree(mem->buf_mem) != cudaSuccess)
		warnx("cudaFree() failed");
free_mem:
	free(mem);

	return NULL;
}

static void cuda_free(struct memory_buffer *mem)
{
	if (mem->fd)
		close(mem->fd);
	if (mem->buf_mem)
		cudaFree(mem->buf_mem);

	free(mem);
}

void cuda_memcpy_to_device(struct memory_buffer *dst, size_t off,
			   void *src, int n)
{
	int ret;

	ret = cudaMemcpy((void *)(dst->buf_mem + off), src, n, cudaMemcpyHostToDevice);
	if (ret != CUDA_SUCCESS)
		warnx("cudaMemcpy() failed");
}

static int cuda_prep(struct memory_buffer *mem)
{
	if (mem && mem->provider == MEMORY_PROVIDER_CUDA) {
		if (cudaIpcOpenMemHandle((void**)&mem->buf_mem, mem->cuda.handle,
					 cudaIpcMemLazyEnablePeerAccess) == cudaSuccess) {
			if (mem->cuda.host_buf_size > 0) {
				mem->cuda.host_buf = malloc(mem->cuda.host_buf_size);
				if (mem->cuda.host_buf == NULL) {
					warnx("malloc cuda validation host_buf failed");
					mem->cuda.host_buf_size = 0;
					return -1;
				}
			}
		} else {
			warnx("cudaIpcOpenMemHandle failed");
			mem->buf_mem = NULL;
			mem->cuda.host_buf_size = 0;
			return -1;
		}
	}

	return 0;
}

static void cuda_exit(struct memory_buffer *mem)
{
	if (mem && mem->provider == MEMORY_PROVIDER_CUDA) {
		if (mem->buf_mem && cudaIpcCloseMemHandle(mem->buf_mem) != cudaSuccess) {
			warnx("cudaIpcCloseMemHandle failed");
		}
		if (mem->cuda.host_buf) {
			free(mem->cuda.host_buf);
			mem->cuda.host_buf_size = 0;
		}
	}
}

static struct memory_provider cuda_memory_provider = {
	.dev_init = cuda_dev_init,
	.alloc = cuda_alloc,
	.free = cuda_free,
	.memcpy_to_device = cuda_memcpy_to_device,
	.prep = cuda_prep,
	.exit = cuda_exit,
};
#endif

struct memory_provider *get_memory_provider(enum memory_provider_type provider)
{
	switch (provider) {
	case MEMORY_PROVIDER_HOST:
		return &udmabuf_memory_provider;
#ifdef USE_CUDA
	case MEMORY_PROVIDER_CUDA:
		return &cuda_memory_provider;
#endif
	default:
		warn("invalid provider: %d", provider);
		return NULL;
	}
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

	ifindex = find_iface(&addr, ifname);
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

/* Setup Devmem RX */
static int __devmem_setup(struct session_state_devmem *devmem, int fd,
			  size_t dmabuf_rx_size_mb, int num_queues,
			  struct pci_dev *dev)
{
	struct netdev_queue_id *queues;
	struct ynl_error yerr;
	int max_kernel_queue;
	int ifindex;
	int ret;

	ret = reserve_queues(fd, num_queues, devmem->ifname, &ifindex,
			     &max_kernel_queue, &devmem->rss_context);
	if (ret)
		return ret;

	rxmp = get_memory_provider(devmem->rx_provider);
	if (!rxmp) {
		ret = -1;
		goto undo_queues;
	}

	devmem->ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!devmem->ys) {
		warnx("Failed to setup YNL socket: %s", yerr.msg);
		goto undo_queues;
	}

	if (rxmp->dev_init && rxmp->dev_init(dev) < 0) {
		ret = -1;
		goto sock_destroy;
	}

	devmem->mem = rxmp->alloc(dmabuf_rx_size_mb * 1024 * 1024);
	if (!devmem->mem) {
		warnx("Failed to allocate memory");
		ret = -1;
		goto sock_destroy;
	}

	queues = calloc(num_queues, sizeof(*queues));
	if (!queues) {
		warn("Failed to allocate memory for queues");
		ret = -1;
		goto free_memory;
	}

	for (int i = 0; i < num_queues; i++) {
		queues[i]._present.type = 1;
		queues[i]._present.id = 1;
		queues[i].type = NETDEV_QUEUE_TYPE_RX;
		queues[i].id = max_kernel_queue + i;
	}

        devmem->mem->dmabuf_id = bind_rx_queue(ifindex, devmem->mem->fd, queues,
                                          num_queues, devmem->ys);
        if (devmem->mem->dmabuf_id < 0) {
		warnx("Failed to bind RX queue");
		ret = -1;
		goto free_queues;
	}

	return 0;

free_queues:
	free(queues);
free_memory:
	rxmp->free(devmem->mem);
sock_destroy:
	ynl_sock_destroy(devmem->ys);
	devmem->ys = NULL;
undo_queues:
	unreserve_queues(devmem->ifname, devmem->rss_context);

	return ret;
}

static int __devmem_teardown(struct session_state_devmem *devmem)
{
	unreserve_queues(devmem->ifname, devmem->rss_context);
	if (devmem->ys)
		ynl_sock_destroy(devmem->ys);
	if (rxmp)
		rxmp->free(devmem->mem);

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

static int devmem_validate_host(struct memory_buffer *mem, __u64 offset,
				__u32 pat_start, __u32 size)
{
	struct dma_buf_sync sync = {};
	void *pat = NULL;
	int ret = 0;

	sync.flags = DMA_BUF_SYNC_START;
	ioctl(mem->fd, DMA_BUF_IOCTL_SYNC, &sync);

	pat = &patbuf[pat_start];
	ret = memcmp(pat, mem->buf_mem + offset, size);

	sync.flags = DMA_BUF_SYNC_END;
	ioctl(mem->fd, DMA_BUF_IOCTL_SYNC, &sync);

	if (ret) {
		warnx("Data corruption %d %d %d %d",
		      *(char *)mem->buf_mem, *(char *)pat, size, pat_start);
		return -1;
	}

	return 0;
}

static int devmem_validate_cuda(struct memory_buffer *mem, __u64 offset,
				__u32 pat_start, __u32 size)
{
#ifdef USE_CUDA
	void *pat = NULL, *hostbuf = NULL;
	int ret = 0;

	if (size > mem->cuda.host_buf_size) {
		warnx("validate size=%d larger than host_buf_size=%ld", size, mem->cuda.host_buf_size);
		return -1;
	}

	hostbuf = mem->cuda.host_buf;
    ret = cudaMemcpy(hostbuf, (void *)(mem->buf_mem + offset), size, cudaMemcpyDeviceToHost);
	if (ret != CUDA_SUCCESS) {
		warnx("cudaMemcpyDeviceToHost failed rc=%d", ret);
		return -1;
	}

	pat = &patbuf[pat_start];
	ret = memcmp(pat, hostbuf, size);
	if (ret) {
		warnx("Data corruption %d %d %d %d",
		      *(char *)hostbuf, *(char *)pat, size, pat_start);
		return -1;
	}
#endif

	return 0;
}

static int devmem_validate_token(struct memory_buffer *mem,
				 struct cmsghdr *cm, int rep, __u64 *tot_recv)
{
	struct dmabuf_cmsg *dmabuf_cmsg = (struct dmabuf_cmsg *)CMSG_DATA(cm);
	size_t start = 0;
	int ret = 0;

	start = *tot_recv % PATTERN_PERIOD;
	if (start + dmabuf_cmsg->frag_size > ARRAY_SIZE(patbuf)) {
		warnx("dmabuf fragment size too big rep=%d", rep);
		return -1;
	}

	if (mem->provider == MEMORY_PROVIDER_CUDA) {
		ret = devmem_validate_cuda(mem, dmabuf_cmsg->frag_offset, start, dmabuf_cmsg->frag_size);
	} else {
		ret = devmem_validate_host(mem, dmabuf_cmsg->frag_offset, start, dmabuf_cmsg->frag_size);
	}
	if (ret) {
		warnx("token validation failed rep=%d rc=%d", rep, ret);
		return -1;
	}

	*tot_recv += dmabuf_cmsg->frag_size;
	return ret;
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

int devmem_sendmsg(int fd, int dmabuf_id, size_t off, size_t n)
{
	char ctrl_data[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;

	iov.iov_base = (void *)off;
	iov.iov_len = n;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = ctrl_data;
	msg.msg_controllen = sizeof(ctrl_data);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_DEVMEM_DMABUF;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(cmsg)) = dmabuf_id;

	return sendmsg(fd, &msg, MSG_ZEROCOPY);
}

int devmem_bind_socket(struct session_state_devmem *devmem, int fd)
{
	char ifname[IFNAMSIZ] = {};
	int ifindex;

	ifindex = find_iface(&devmem->addr, ifname);
	if (ifindex < 0) {
		warnx("Failed to resolve ifindex: %s", strerror(-ifindex));
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ)) {
		warn("failed to bind device to socket");
		return -1;
	}

	return 0;
}

static int __devmem_setup_tx(struct session_state_devmem *devmem, int dmabuf_tx_size_mb,
			     struct pci_dev *dev, struct sockaddr_in6 *addr)
{
	char ifname[IFNAMSIZ] = {};
	struct ynl_error yerr;
	int ifindex;
	int ret;

	devmem->dmabuf_tx_size_mb = dmabuf_tx_size_mb;
	memcpy(&devmem->tx_dev, dev, sizeof(devmem->tx_dev));
	memcpy(&devmem->addr, addr, sizeof(devmem->addr));

	txmp = get_memory_provider(devmem->tx_provider);
	if (!txmp)
		return -1;

	if (txmp->dev_init && txmp->dev_init(&devmem->tx_dev) < 0)
		return -1;

	devmem->tx_mem = txmp->alloc(devmem->dmabuf_tx_size_mb * 1024 * 1024);
	if (!devmem->tx_mem) {
		warnx("Failed to allocate devmem tx buffer");
		return -1;
	}

	txmp->memcpy_to_device(devmem->tx_mem, 0, patbuf, sizeof(patbuf));

	ifindex = find_iface(&devmem->addr, ifname);
	if (ifindex < 0) {
		warnx("Failed to resolve ifindex: %s", strerror(-ifindex));
		return -1;
	}

	devmem->ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!devmem->ys) {
		warnx("Failed to setup YNL socket: %s", yerr.msg);
		return -1;
	}

	devmem->tx_mem->dmabuf_id = bind_tx_queue(ifindex, devmem->tx_mem->fd, devmem->ys);
	if (devmem->tx_mem->dmabuf_id < 0) {
		warnx("Failed to bind TX queue dmabuf: %d\n", devmem->tx_mem->dmabuf_id);
		ret = -1;
		goto sock_destroy;
	}


	return 0;

sock_destroy:
	ynl_sock_destroy(devmem->ys);
	devmem->ys = NULL;
	return ret;
}

static void __devmem_teardown_tx(struct session_state_devmem *devmem)
{
	if (txmp && devmem->tx_mem) {
		txmp->free(devmem->tx_mem);
		devmem->tx_mem = NULL;
	}

	if (devmem->ys) {
		ynl_sock_destroy(devmem->ys);
		devmem->ys = NULL;
	}
}

static void devmem_cuda_ctx_worker_main(struct cuda_ctx_worker_opts *opts)
{
	struct kpm_header *hdr = NULL;
	int fd = opts->kpm_fd;

	kpm_dbg("cuda_ctx worker waiting for message pid=%d", getpid());

	hdr = kpm_receive(fd);
	if (!hdr) {
		kpm_dbg("cuda_ctx recv no msg");
		return;
	}

	/* only KPM_MSG_WORKER_KILL will be received */
	kpm_dbg("cuda_ctx worker recv msg type: %d", hdr->type);

	free(hdr);
}

static int devmem_worker_setup_cuda_ctx(struct session_state_devmem *devmem,
					struct cuda_ctx_worker_opts *opts)
{
	struct kpm_cuda_init_done init_done;
	int ret = 0;

	kpm_dbg("cuda_ctx worker pid=%d is setting up cuda.", getpid());

	if (opts->type == CUDA_OPT_TYPE_SETUP_RX) {
		ret = __devmem_setup(devmem, opts->tcp_fd, opts->dmabuf_size_mb,
				     opts->num_queues, opts->dev);
	} else {
		ret = __devmem_setup_tx(devmem, opts->dmabuf_size_mb,
					opts->dev, opts->addr);
	}
	if (ret < 0) {
		warnx("Failed to setup devmem");
		return -1;
	}

	memset(&init_done, 0, sizeof(init_done));
#ifdef USE_CUDA
	if (opts->type == CUDA_OPT_TYPE_SETUP_RX) {
		init_done.ipc_mem_handle = devmem->mem->cuda.handle;
		init_done.dmabuf_id = devmem->mem->dmabuf_id;
	} else {
		init_done.ipc_mem_handle = devmem->tx_mem->cuda.handle;
		init_done.dmabuf_id = devmem->tx_mem->dmabuf_id;
	}
#endif

	if (kpm_send_cuda_init_done(opts->kpm_fd, &init_done) < 1) {
		warnx("Notify cuda_init done fail");
		if (opts->type == CUDA_OPT_TYPE_SETUP_RX)
			__devmem_teardown(devmem);
		else
			__devmem_teardown_tx(devmem);
		return -1;
	}

	devmem_cuda_ctx_worker_main(opts);

	kpm_dbg("cuda_ctx worker pid=%d is tearing down cuda.", getpid());
	if (opts->type == CUDA_OPT_TYPE_SETUP_RX)
		__devmem_teardown(devmem);
	else
		__devmem_teardown_tx(devmem);

	return 0;
}

static int devmem_store_cuda_ctx(struct session_state_devmem *devmem,
				 struct cuda_ctx_worker_opts *opts)
{
	struct kpm_cuda_init_done *init_done = NULL;
	struct memory_buffer *mem = NULL;

	kpm_dbg("server session pid=%d waiting for cuda_ctx from worker pid=%d.", getpid(), opts->pid);

	init_done = kpm_receive(opts->kpm_fd);
	if (!init_done) {
		warnx("No init_done notification from cuda_ctx worker pid=%d", opts->pid);
		goto err_worker_kill;
	}

	if (!kpm_good_req(init_done, KPM_MSG_WORKER_CUDA_INIT_DONE)) {
		warnx("Invalid KPM_MSG_WORKER_CUDA_INIT_DONE ack type=%d len=%d", init_done->hdr.type, init_done->hdr.len);
		goto err_worker_kill;
	}

	mem = malloc(sizeof(struct memory_buffer));
	if (!mem) {
		warnx("malloc memory_buffer fail");
		goto err_worker_kill;
	}
	memset(mem, 0, sizeof(struct memory_buffer));
#ifdef USE_CUDA
	mem->cuda.handle = init_done->ipc_mem_handle;
#endif
	mem->provider = MEMORY_PROVIDER_CUDA;
	mem->dmabuf_id = init_done->dmabuf_id;
	mem->cuda.ctx_pid = opts->pid;
	mem->cuda.ctx_kpm_fd = opts->kpm_fd;
	mem->size = opts->dmabuf_size_mb * 1024 * 1024;

	if (opts->type == CUDA_OPT_TYPE_SETUP_RX) {
		devmem->mem = mem;
		mem->cuda.host_buf_size = devmem->validate_buf_size;
	} else {
		devmem->tx_mem = mem;
		devmem->dmabuf_tx_size_mb = opts->dmabuf_size_mb;
		memcpy(&devmem->tx_dev, opts->dev, sizeof(devmem->tx_dev));
		memcpy(&devmem->addr, opts->addr, sizeof(devmem->addr));
	}

	kpm_dbg("server session pid=%d received cuda_ctx from worker pid=%d and updated state",
			getpid(), opts->pid);

	free(init_done);
	return 0;

err_worker_kill:
	kpm_send_empty(opts->kpm_fd, KPM_MSG_WORKER_KILL);
	waitpid(opts->pid, NULL, 0);
	close(opts->kpm_fd);
	if (init_done)
		free(init_done);

	return -1;
}

/* Sharing CUDA context between processes is not straightforward.
 * Setting up the context in the parent and using it in the (forked) child is not supported.
 * Initialize and manage CUDA context in a separate worker then share via cudaIpcMemHandle_t
 */
static int devmem_spawn_cuda_ctx_worker(struct session_state_devmem *devmem,
					struct cuda_ctx_worker_opts *opts)
{
	int p[2], ret = 0;
	pid_t pid = 0;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, p) < 0) {
		warn("create socketpair fail");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		warn("Failed to fork");
		close(p[0]);
		close(p[1]);
		return -1;
	}

	if (!pid) {
		close(p[0]);
		opts->kpm_fd = p[1];
		ret = devmem_worker_setup_cuda_ctx(devmem, opts);
		close(p[1]);
		kpm_dbg("cuda_ctx worker pid=%d exiting. ret=%d", getpid(), ret);
		if (ret != 0)
			exit(1);
		else
			exit(0);
	}

	close(p[1]);
	opts->kpm_fd = p[0];
	opts->pid = pid;

	kpm_dbg("server session pid=%d spawn cuda_ctx worker pid=%d.", getpid(), pid);

	return devmem_store_cuda_ctx(devmem, opts);
}

int devmem_setup(struct session_state_devmem *devmem, int fd,
		 size_t dmabuf_rx_size_mb, int num_queues,
		 enum memory_provider_type provider,
		 struct pci_dev *dev)
{
	devmem->rx_provider = provider;

	if (provider == MEMORY_PROVIDER_CUDA) {
		struct cuda_ctx_worker_opts opts = {
			.type = CUDA_OPT_TYPE_SETUP_RX,
			.tcp_fd = fd,
			.dmabuf_size_mb = dmabuf_rx_size_mb,
			.num_queues = num_queues,
			.dev = dev,
		};
		return devmem_spawn_cuda_ctx_worker(devmem, &opts);
	} else {
		return __devmem_setup(devmem, fd, dmabuf_rx_size_mb, num_queues, dev);
	}
}

int devmem_setup_tx(struct session_state_devmem *devmem, enum memory_provider_type provider,
		    int dmabuf_tx_size_mb, struct pci_dev *dev, struct sockaddr_in6 *addr)
{
	devmem->tx_provider = provider;

	if (provider == MEMORY_PROVIDER_CUDA) {
		struct cuda_ctx_worker_opts opts = {
			.type = CUDA_OPT_TYPE_SETUP_TX,
			.dmabuf_size_mb = dmabuf_tx_size_mb,
			.dev = dev,
			.addr = addr,
		};
		return devmem_spawn_cuda_ctx_worker(devmem, &opts);
	} else {
		return __devmem_setup_tx(devmem, dmabuf_tx_size_mb, dev, addr);
	}
}

static int devmem_free_cuda_ctx_worker(struct session_state_devmem *devmem,
				       struct cuda_ctx_worker_opts *opts)
{
	struct memory_buffer *mem = NULL;

	kpm_dbg("server session pid=%d freeing cuda_ctx worker. type=%d", getpid(), opts->type);

	if (opts->type == CUDA_OPT_TYPE_TEARDOWN_RX) {
		mem = devmem->mem;
		devmem->mem = NULL;
	} else if (opts->type == CUDA_OPT_TYPE_TEARDOWN_TX) {
		mem = devmem->tx_mem;
		devmem->tx_mem = NULL;
	}

	if (mem && mem->cuda.ctx_pid > 0) {
		kpm_send_empty(mem->cuda.ctx_kpm_fd, KPM_MSG_WORKER_KILL);
		waitpid(mem->cuda.ctx_pid, NULL, 0);
		close(mem->cuda.ctx_kpm_fd);
	}

	if (mem)
		free(mem);

	return 0;
}

int devmem_teardown(struct session_state_devmem *devmem)
{
	if (devmem->rx_provider == MEMORY_PROVIDER_CUDA) {
		struct cuda_ctx_worker_opts opts = {
			.type = CUDA_OPT_TYPE_TEARDOWN_RX,
		};
		return devmem_free_cuda_ctx_worker(devmem, &opts);
	} else {
		return __devmem_teardown(devmem);
	}
}

void devmem_teardown_tx(struct session_state_devmem *devmem)
{
	if (devmem->tx_provider == MEMORY_PROVIDER_CUDA) {
		struct cuda_ctx_worker_opts opts = {
			.type = CUDA_OPT_TYPE_TEARDOWN_TX,
		};
		devmem_free_cuda_ctx_worker(devmem, &opts);
	} else {
		__devmem_teardown_tx(devmem);
	}
}
