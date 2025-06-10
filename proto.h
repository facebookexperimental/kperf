/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef PROTO_H
#define PROTO_H 1

#include <netdb.h>
#include <linux/tls.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/socket.h>

#define KPERF_MAX_CPUS	1024

enum kpm_msg_type {
	KPM_MSG_TYPE_ERROR = 1,
	KPM_MSG_TYPE_ECHO,
	KPM_MSG_TYPE_HELLO,
	KPM_MSG_TYPE_SPAWN_PWORKER,
	KPM_MSG_TYPE_PIN_WORKER,
	KPM_MSG_TYPE_OPEN_TCP_ACCEPTOR,
	KPM_MSG_TYPE_CONNECT,
	KPM_MSG_TYPE_DISCONNECT,
	KPM_MSG_TYPE_CONNECTION_ID,
	KPM_MSG_TYPE_TLS,
	KPM_MSG_TYPE_MAX_PACING,
	KPM_MSG_TYPE_TCP_CC,
	KPM_MSG_TYPE_MODE,
	KPM_MSG_TYPE_TEST,
	KPM_MSG_TYPE_TEST_RESULT,
	KPM_MSG_TYPE_END_TEST,

	KPM_MSG_WORKER_ID,
	KPM_MSG_WORKER_KILL,
	KPM_MSG_WORKER_TEST,
	KPM_MSG_WORKER_END_TEST,
	KPM_MSG_WORKER_TEST_RESULT,

	__KPM_MSG_TOTAL,

	KPM_MSG_REPLY		= 0x8000
};

struct kpm_header {
	__u16 type;
	__u16 id;
	__u32 len;
};

struct kpm_empty {
	struct kpm_header hdr;
};

struct kpm_hello {
	struct kpm_header hdr;
	__u32 version;
	__u32 n_cpus;
};

struct __kpm_generic_u16 {
	struct kpm_header hdr;
	__u16 val;
	__u16 pad;
};

struct kpm_tcp_acceptor_reply {
	struct kpm_header hdr;
	socklen_t len;
	struct sockaddr_in6 addr;
};

struct __kpm_generic_u32 {
	struct kpm_header hdr;
	__u32 val;
};

struct kpm_reply_error {
	struct kpm_header hdr;
	__u16 type;
	__u16 error;
};

struct kpm_pin_worker {
	struct kpm_header hdr;
	__u32 worker_id;
	__u32 cpu;
};

struct kpm_connect {
	struct kpm_header hdr;
	socklen_t len;
	struct sockaddr_in6 addr;
	__u32 mss;
};

struct kpm_connect_reply {
	struct kpm_header hdr;
	struct {
		__u32 id;
		__u32 cpu;
		__u16 port;
	} local, remote;
};

struct kpm_connection_id {
	struct kpm_header hdr;
	__u32 id;
	__u32 cpu;
};

struct kpm_max_pacing {
	struct kpm_header hdr;
	__u32 id;
	__u32 max_pacing;
};

#define KPM_CC_NAME_LEN 16

struct kpm_tcp_cc {
	struct kpm_header hdr;
	__u32 id;
	char cc_name[KPM_CC_NAME_LEN];
};

enum kpm_rx_mode {
	KPM_RX_MODE_SOCKET,
	KPM_RX_MODE_SOCKET_TRUNC,
	KPM_RX_MODE_DEVMEM,
};

enum kpm_tx_mode {
	KPM_TX_MODE_SOCKET,
	KPM_TX_MODE_SOCKET_ZEROCOPY,
	KPM_TX_MODE_DEVMEM,
};

enum memory_provider_type {
	MEMORY_PROVIDER_HOST,
	MEMORY_PROVIDER_CUDA,
};

#define DEVICE_DOMAIN_ANY 0xffff
#define DEVICE_BUS_ANY 0xff
#define DEVICE_DEVICE_ANY 0xff

struct pci_dev {
	__u16 domain;
	__u8 bus;
	__u8 device;
};

struct kpm_mode {
	struct kpm_header hdr;
	enum kpm_rx_mode rx_mode;
	enum kpm_tx_mode tx_mode;

	/* devmem info */
	enum memory_provider_type rx_provider;
	struct pci_dev dev;
	__u32 dmabuf_rx_size_mb;
	__u32 dmabuf_tx_size_mb;
	__u32 num_rx_queues;
	struct sockaddr_in6 addr;

	__u8 validate;
};

enum kpm_tls_mask {
	KPM_TLS_ULP = 1,
	KPM_TLS_TX = 2,
	KPM_TLS_RX = 4,
	KPM_TLS_NOPAD = 8,
};

struct kpm_tls {
	struct kpm_header hdr;
	__u32 connection_id;
	__u32 dir_mask;
	socklen_t len;
	union {
		struct tls12_crypto_info_aes_gcm_128 aes128;
	} info;
};

struct kpm_end_test {
	struct kpm_header hdr;
	__u32 id;
};

enum kpm_test_type {
	KPM_TEST_TYPE_STREAM = 1,
	KPM_TEST_TYPE_RR,
};

#define KPM_DFL_OP_CHUNK		(1 << 16)
#define KPM_MAX_OP_CHUNK		(1 << 27)

struct kpm_test {
	struct kpm_header hdr;
	__u8 active;
	__u8 pad;
	__u16 time_sec;
	__u32 n_conns;
	__u32 test_id;
	struct kpm_test_spec {
		__u32 connection_id;
		__u32 worker_id;
		enum kpm_test_type type;
		__u32 read_size;
		__u32 write_size;
		union kpm_test_arg {
			struct {
				__u32 req_size;
				__u32 resp_size;
				__u8 timings;
			} rr;
		} arg;
	} specs[0];
};

struct kpm_test_results {
	struct kpm_header hdr;
	__u32 time_usec;
	__u32 n_conns;
	__u32 test_id;
	struct kpm_cpu_load {
		__u16 id;
		__u16 user; /* sum of user and nice */
		__u16 system;
		__u16 idle;
		__u16 iowait;
		__u16 irq;
		__u16 sirq;
	} cpu_load[KPERF_MAX_CPUS];
	struct kpm_test_result {
		__u32 connection_id;
		__u32 worker_id;
		enum kpm_test_type type;
		__u64 rx_bytes;
		__u64 tx_bytes;

		__u32 reqs;

		__u32 retrans;
		__u32 reord_seen;
		__u32 rtt;
		__u32 rttvar;
		__u32 delivered_ce;
		__u32 snd_wnd;
		__u32 snd_cwnd;

		__u32 lat_hist[33];
		__u32 p25;
		__u32 p50;
		__u32 p90;
		__u32 p99;
		__u32 p999;
		__u32 p9999;
	} res[0];
};

#define kpm_good_req(msg, msg_type)					\
	({								\
		struct kpm_header *_hdr = &(msg)->hdr;			\
		int _ret;						\
									\
		_ret = _hdr->type == (msg_type) &&			\
			_hdr->len == sizeof(*msg);			\
		_ret;							\
	})

#define kpm_good_reply(msg, msg_type, seq)				\
	({								\
		struct kpm_header *_hdr = &(msg)->hdr;			\
		int _ret;						\
									\
		_ret = _hdr->type == ((msg_type) | KPM_MSG_REPLY) &&	\
			_hdr->id == (seq) &&				\
			_hdr->len == sizeof(*msg);			\
		_ret;							\
	})

void *kpm_msg_dup(struct kpm_header *hdr);

void *kpm_receive(int fd);

int kpm_send(int fd, struct kpm_header *msg, size_t size,
	     enum kpm_msg_type type);
int kpm_send_empty(int fd, enum kpm_msg_type type);
int kpm_send_u32(int fd, enum kpm_msg_type type, __u32 arg);

int kpm_send_conn_id(int fd, __u32 id, __u32 cpu);
int kpm_send_connect(int fd, struct sockaddr_in6 *addr, socklen_t len,
		     __u32 mss);
int kpm_send_tls(int fd, __u32 conn_id, __u32 dir_mask,
		 void *info, socklen_t len);
int kpm_send_max_pacing(int fd, __u32 id, __u32 max_pace);
int kpm_send_tcp_cc(int fd, __u32 id, char *cc_name);
int kpm_send_mode(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
		  __u32 dmabuf_rx_size_mb, __u32 dmabuf_tx_size_mb,
		  __u32 num_rx_queues, __u8 validate,
		  enum memory_provider_type rx_provider,
		  struct pci_dev *dev, struct sockaddr_in6 *addr);
int kpm_send_pin_worker(int fd, __u32 id, __u32 cpu);

void kpm_reply_error(int fd, struct kpm_header *hdr, __u16 error);

int kpm_reply_empty(int fd, struct kpm_header *hdr);
int kpm_reply_u16(int fd, struct kpm_header *hdr, __u16 arg);
int kpm_reply_u32(int fd, struct kpm_header *hdr, __u32 arg);

int kpm_reply_acceptor(int fd, struct kpm_header *hdr,
		       struct sockaddr_in6 *addr, socklen_t len);
int kpm_reply_connect(int fd, struct kpm_header *hdr,
		      __u32 local_id, __u32 local_cpu, __u16 local_port,
		      __u32 remote_id, __u32 remote_cpu, __u16 remote_port);

int kpm_xchg_hello(int fd, unsigned int *ncpus);

int kpm_req_tcp_sock(int fd, struct sockaddr_in6 *addr, socklen_t *len);
int kpm_req_end_test(int fd, __u32 test_id);
int kpm_req_tls(int fd, __u32 conn_id, __u32 dir_mask,
		void *info, socklen_t len);
int kpm_req_pacing(int fd, __u32 conn_id, __u32 max_pace);
int kpm_req_tcp_cc(int fd, __u32 conn_id, char *cc_name);
int kpm_req_mode(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
		 __u32 dmabuf_rx_size_mb, __u32 dmabuf_tx_size_mb,
		 __u32 num_rx_queues, __u8 validate,
		 enum memory_provider_type rx_provider,
		 struct pci_dev *dev, struct sockaddr_in6 *addr);
int kpm_req_disconnect(int fd, __u32 connection_id);

#endif /* PROTO_H */
