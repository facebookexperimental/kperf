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

struct server_session {
	int cfd;
	pid_t pid;
	struct list_node sessions;
};

#ifndef MSG_SOCK_DEVMEM
#define MSG_SOCK_DEVMEM 0x2000000
#define SO_DEVMEM_LINEAR 78
#define SO_DEVMEM_DMABUF 79
#define SO_DEVMEM_DONTNEED 80

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
#endif

struct connection_devmem {
	struct dmabuf_token rxtok[128];
	int rxtok_len;
	/* ncdevmem uses 80k, allocate 64k for recvmsg tokens */
	char ctrl_data[64 * 1024];
};

struct session_state_devmem {
	struct ynl_sock *ys;
	char ifname[IFNAMSIZ];
	int dmabuf_id;
	int dmabuf_fd;
	int udmabuf_devfd;
	int udmabuf_memfd;
	bool udmabuf_valid;
};

struct server_session *
server_session_spawn(int fd, struct sockaddr_in6 *addr, socklen_t *addrlen);

void NORETURN pworker_main(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode);

int devmem_setup(struct session_state_devmem *devmem, int fd,
		 size_t udmabuf_size);
int devmem_teardown(struct session_state_devmem *devmem);
int devmem_release_tokens(int fd, struct connection_devmem *conn);
ssize_t devmem_recv(int fd, struct connection_devmem *conn,
		    unsigned char *rxbuf, size_t chunk, int rep);

#endif /* SERVER_H */
