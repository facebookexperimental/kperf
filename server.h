/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef SERVER_H
#define SERVER_H 1

#include <netdb.h>
#include <net/if.h>
#include <sys/types.h>

#include <ccan/compiler/compiler.h>
#include <ccan/list/list.h>

#include <ynl-c/ynl.h>

#include "proto.h"

#ifdef USE_CUDA
#include <cuda.h>
#endif

#define PATTERN_PERIOD 255

struct server_session {
	int cfd;
	pid_t pid;
	struct list_node sessions;
};

#ifndef MSG_SOCK_DEVMEM
#define MSG_SOCK_DEVMEM 0x2000000
#define SO_DEVMEM_LINEAR 78
#define SO_DEVMEM_DMABUF 79
#define SCM_DEVMEM_DMABUF SO_DEVMEM_DMABUF
#define SO_DEVMEM_DONTNEED 80
#endif

struct dmabuf_cmsg {
	__u64 frag_offset;
	__u32 frag_size;
	__u32 frag_token;
	__u32  dmabuf_id;
	__u32 flags;
};

struct dmabuf_token {
	__u32 token_start;
	__u32 token_count;
};

#ifdef USE_CUDA
struct memory_buffer_cuda {
	CUcontext ctx;
};
#endif

struct memory_buffer {
	char *buf_mem;
	size_t size;
	int fd;
	int devfd;
	int memfd;
	int dmabuf_id;
	void *priv;
#ifdef USE_CUDA
	struct memory_buffer_cuda cuda;
#endif
};

struct memory_provider {
	int (*dev_init)(struct pci_dev *dev);
	struct memory_buffer *(*alloc)(size_t size);
	void (*free)(struct memory_buffer *mem);
	void (*memcpy_to_device)(struct memory_buffer *dst, size_t off,
				 void *src, int n);
	void (*memcpy_from_device)(void *dst, struct memory_buffer *src,
				   size_t off, int n);
};

struct connection_devmem {
	struct dmabuf_token rxtok[128];
	int rxtok_len;
	/* ncdevmem uses 80k, allocate 64k for recvmsg tokens */
	char ctrl_data[64 * 1024];
};

struct session_state_devmem {
	struct ynl_sock *ys;
	char ifname[IFNAMSIZ];

	/* RX */
	struct memory_buffer *mem;
	int rss_context;

	/* TX */
	struct memory_buffer *tx_mem;
	struct pci_dev tx_dev;
	__u32 dmabuf_tx_size_mb;
	enum memory_provider_type tx_provider;
	struct sockaddr_in6 addr;
};

struct worker_state_devmem {
	struct memory_buffer *mem;
	int dmabuf_id;
};

struct server_session *
server_session_spawn(int fd, struct sockaddr_in6 *addr, socklen_t *addrlen);

void NORETURN pworker_main(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
			   struct memory_buffer *devmem, bool validate,
			   int dmabuf_id);

int devmem_setup(struct session_state_devmem *devmem, int fd,
		 size_t dmabuf_size, int num_queues,
		 enum memory_provider_type provider, struct pci_dev *dev);
int devmem_teardown(struct session_state_devmem *devmem);
void devmem_teardown_tx(struct session_state_devmem *devmem);
int devmem_release_tokens(int fd, struct connection_devmem *conn);
ssize_t devmem_recv(int fd, struct connection_devmem *conn,
		    unsigned char *rxbuf, size_t chunk, struct memory_buffer *mem,
		    int rep, __u64 tot_recv, bool validate);
int devmem_sendmsg(int fd, int dmabuf_id, size_t off, size_t n);
void devmem_teardown_conn(struct connection_devmem *devmem);
int devmem_prepare_connect(int fd, struct sockaddr_in6 *src, struct session_state_devmem *devmem);
int devmem_setup_tx(struct session_state_devmem *devmem, enum memory_provider_type provider,
		    int dmabuf_tx_size_mb, struct pci_dev *dev, struct sockaddr_in6 *addr);
int devmem_bind_socket(struct session_state_devmem *devmem, int fd);
#endif /* SERVER_H */
