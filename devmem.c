// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/dma-buf.h>
#include <linux/memfd.h>
#include <linux/udmabuf.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>

#include <ynl-c/netdev.h>

#include "server.h"
#include "proto_dbg.h"
#include "rx_steering.h"

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif
#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB (21U << 26)
#endif

#define HUGEPAGE_2MB (2UL * 1024 * 1024)

#ifdef USE_CUDA
#include <cuda.h>
#include <cuda_runtime.h>

#ifdef CU_MEM_RANGE_FLAG_DMA_BUF_MAPPING_TYPE_PCIE
#define CUDA_FLAGS CU_MEM_RANGE_FLAG_DMA_BUF_MAPPING_TYPE_PCIE
#else
#define CUDA_FLAGS 0
#endif
#endif

extern unsigned char patbuf[KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1];

static int bind_rx_queue(unsigned int ifindex, unsigned int dmabuf_fd,
			 struct netdev_queue_id *queues,
			 unsigned int n_queue_index, __u32 rx_page_size,
			 struct ynl_sock *ys)
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
	if (rx_page_size)
		netdev_bind_rx_req_set_rx_page_size(req, rx_page_size);

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

static struct memory_buffer *udmabuf_alloc(size_t size, __u32 rx_page_size)
{
	unsigned int memfd_flags = MFD_ALLOW_SEALING;
	long page_sz = sysconf(_SC_PAGESIZE);
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

	if (rx_page_size && (long)rx_page_size > page_sz)
		memfd_flags |= MFD_HUGETLB | MFD_HUGE_2MB;

	mem->memfd = memfd_create("udmabuf-test", memfd_flags);
	if (mem->memfd < 0) {
		warn("memfd_create() failed");
		goto close_devfd;
	}

	ret = fcntl(mem->memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0) {
		warn("fcntl() failed");
		goto close_memfd;
	}

	/* hugetlbfs only accepts hugepage-aligned sizes. */
	if (memfd_flags & MFD_HUGETLB)
		size = (size + HUGEPAGE_2MB - 1) & ~(HUGEPAGE_2MB - 1);

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

static struct memory_buffer *cuda_alloc(size_t size, __u32 rx_page_size __attribute__((unused)))
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
	if (ret != cudaSuccess)
		goto free_mem;

	ret = cuMemGetHandleForAddressRange((void *)&mem->fd,
					    ((CUdeviceptr)mem->buf_mem), size,
					    CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD,
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

	ret = cudaMemcpy((void *)(dst->buf_mem + off), src, n,
			 cudaMemcpyHostToDevice);
	if (ret != cudaSuccess)
		warnx("cudaMemcpy() failed");
}

static struct memory_provider cuda_memory_provider = {
	.dev_init = cuda_dev_init,
	.alloc = cuda_alloc,
	.free = cuda_free,
	.memcpy_to_device = cuda_memcpy_to_device,
};
#endif

static struct memory_provider *get_memory_provider(enum memory_provider_type provider)
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

/* Setup Devmem RX */
int devmem_setup(struct session_state_devmem *devmem,
		 struct rx_steering *steering, size_t dmabuf_rx_size_mb,
		 int num_queues, __u32 rx_page_size,
		 enum memory_provider_type provider,
		 struct pci_dev *dev)
{
	struct netdev_queue_id *queues;
	struct ynl_error yerr;
	int ret;

	rxmp = get_memory_provider(provider);
	if (!rxmp) {
		ret = -1;
		goto undo_queues;
	}

	devmem->ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!devmem->ys) {
		warnx("Failed to setup YNL socket: %s", yerr.msg);
		ret = -1;
		goto undo_queues;
	}

	if (rxmp->dev_init && rxmp->dev_init(dev) < 0) {
		ret = -1;
		goto sock_destroy;
	}

	devmem->mem = rxmp->alloc(dmabuf_rx_size_mb * 1024 * 1024, rx_page_size);
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
		queues[i].id = steering->queue_id + i;
	}

	devmem->mem->dmabuf_id = bind_rx_queue(steering->ifindex,
					       devmem->mem->fd, queues,
					       num_queues, rx_page_size,
					       devmem->ys);
	if (devmem->mem->dmabuf_id < 0) {
		warnx("Failed to bind RX queue");
		ret = -1;
		goto free_memory;
	}

	return 0;

free_memory:
	rxmp->free(devmem->mem);
	devmem->mem = NULL;
sock_destroy:
	ynl_sock_destroy(devmem->ys);
	devmem->ys = NULL;
undo_queues:
	rx_steering_teardown(steering);
	return ret;
}

int devmem_teardown(struct session_state_devmem *devmem)
{
	if (devmem->ys) {
		ynl_sock_destroy(devmem->ys);
		devmem->ys = NULL;
	}
	if (rxmp && devmem->mem) {
		rxmp->free(devmem->mem);
		devmem->mem = NULL;
	}
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

static int devmem_validate_cuda(unsigned char *rxbuf, struct memory_buffer *mem,
				__u64 offset, __u32 pat_start, __u32 size)
{
#ifdef USE_CUDA
	void *pat = NULL;
	int ret = 0;

	ret = cudaMemcpy(rxbuf, (void *)(mem->buf_mem + offset), size,
			 cudaMemcpyDeviceToHost);
	if (ret != cudaSuccess) {
		warnx("cudaMemcpyDeviceToHost failed rc=%d", ret);
		return -1;
	}

	pat = &patbuf[pat_start];
	ret = memcmp(pat, rxbuf, size);
	if (ret) {
		warnx("Data corruption %d %d %d %d",
		      *(char *)rxbuf, *(char *)pat, size, pat_start);
		return -1;
	}
#endif

	return 0;
}

static int devmem_validate_recv(unsigned char *rxbuf, struct memory_buffer *mem,
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

	switch (mem->provider) {
	case MEMORY_PROVIDER_HOST:
		ret = devmem_validate_host(mem, dmabuf_cmsg->frag_offset, start,
					   dmabuf_cmsg->frag_size);
		break;
	case MEMORY_PROVIDER_CUDA:
		ret = devmem_validate_cuda(rxbuf, mem, dmabuf_cmsg->frag_offset,
					   start, dmabuf_cmsg->frag_size);
		break;
	}
	if (ret) {
		warnx("devmem recv validation failed rep=%d rc=%d", rep, ret);
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
			ret = devmem_validate_recv(rxbuf, mem, cm, rep,
						   &tot_recv);
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

	ifindex = rx_steering_find_iface(&devmem->addr, ifname);
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

int devmem_setup_tx(struct session_state_devmem *devmem, enum memory_provider_type provider,
		    int dmabuf_tx_size_mb, struct pci_dev *dev, struct sockaddr_in6 *addr)
{
	char ifname[IFNAMSIZ] = {};
	struct ynl_error yerr;
	int ifindex;
	int ret;

	devmem->tx_provider = provider;
	devmem->dmabuf_tx_size_mb = dmabuf_tx_size_mb;
	memcpy(&devmem->tx_dev, dev, sizeof(devmem->tx_dev));
	memcpy(&devmem->addr, addr, sizeof(devmem->addr));

	txmp = get_memory_provider(devmem->tx_provider);
	if (!txmp)
		return -1;

	if (txmp->dev_init && txmp->dev_init(&devmem->tx_dev) < 0)
		return -1;

	devmem->tx_mem = txmp->alloc(devmem->dmabuf_tx_size_mb * 1024 * 1024, 0);
	if (!devmem->tx_mem) {
		warnx("Failed to allocate devmem tx buffer");
		return -1;
	}

	txmp->memcpy_to_device(devmem->tx_mem, 0, patbuf, sizeof(patbuf));

	ifindex = rx_steering_find_iface(&devmem->addr, ifname);
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

void devmem_teardown_tx(struct session_state_devmem *devmem)
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
