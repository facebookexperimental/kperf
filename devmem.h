// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef DEVMEM_H
#define DEVMEM_H 1

#include <sys/socket.h>

int reserve_queues(int fd, int num_queues, char out_ifname[IFNAMSIZ],
		   int *out_ifindex, int *out_queue_id, int *out_rss_context);
void unreserve_queues(char *ifname, int rss_context);

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

#endif /* DEVMEM_H */
