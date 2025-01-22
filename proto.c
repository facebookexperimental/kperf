// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>

#include <ccan/err/err.h>

#include "proto.h"

static const unsigned int proto_ver =
	__KPM_MSG_TOTAL << 24 |
	sizeof(struct kpm_test) << 16 |
	sizeof(struct kpm_test_results);

void *kpm_msg_dup(struct kpm_header *hdr)
{
	char *msg;

	msg = malloc(hdr->len);
	memcpy(msg, hdr, hdr->len);
	return msg;
}

void *kpm_receive(int fd)
{
	struct kpm_header hdr;
	ssize_t off, n;
	char *msg;

	n = recv(fd, &hdr, sizeof(hdr), MSG_PEEK | MSG_WAITALL);
	if (n < (int)sizeof(hdr)) {
		if (n)
			warn("Failed to receive header (%zd)", n);
		return NULL;
	}
	if (hdr.len < sizeof(hdr)) {
		warnx("Invalid header length (%d)", hdr.len);
		return NULL;
	}

	msg = malloc(hdr.len);
	if (!msg)
		return NULL;

	off = 0;
	while (hdr.len) {
		n = recv(fd, msg + off, hdr.len, 0);
		if (n > hdr.len) {
			warnx("Oversized recv");
		} else if (n <= 0) {
			warnx("Short recv");
		} else {
			off += n;
			hdr.len -= n;
			continue;
		}

		free(msg);
		return NULL;
	}

	return msg;
}

static int __kpm_send(int fd, struct kpm_header *msg, size_t size, int id,
		      enum kpm_msg_type type)
{
	ssize_t n, off;

	msg->type = type;
	msg->id = id;
	msg->len = size;

	off = 0;
	while (size) {
		n = send(fd, (char *)msg + off, size, 0);
		if (n <= 0) {
			warnx("Short send");
			return -1;
		}
		size -= n;
	}

	return id;
}

int kpm_send(int fd, struct kpm_header *msg, size_t size,
	     enum kpm_msg_type type)
{
	static short int id_gen;

	return __kpm_send(fd, msg, size, ++id_gen, type);
}

int kpm_send_empty(int fd, enum kpm_msg_type type)
{
	struct kpm_header hdr;

	return kpm_send(fd, &hdr, sizeof(hdr), type);
}

int kpm_send_u32(int fd, enum kpm_msg_type type, __u32 arg)
{
	struct __kpm_generic_u32 msg;

	msg.val = arg;

	return kpm_send(fd, &msg.hdr, sizeof(msg), type);
}

int kpm_send_conn_id(int fd, __u32 id, __u32 cpu)
{
	struct kpm_connection_id msg;

	msg.id = id;
	msg.cpu = cpu;

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_CONNECTION_ID);
}

int kpm_send_connect(int fd, struct sockaddr_in6 *addr, socklen_t len,
		     __u32 mss)
{
	struct kpm_connect msg;

	if (len > sizeof(msg.addr)) {
		warnx("Oversized connect arg");
		return -1;
	}

	msg.len = len;
	memcpy(&msg.addr, addr, len);
	msg.mss = mss;

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_CONNECT);
}

int
kpm_send_tls(int fd, __u32 conn_id, __u32 dir_mask, void *info, socklen_t len)
{
	struct kpm_tls msg;

	if (len > sizeof(msg.info)) {
		warnx("Oversized TLS arg");
		return -1;
	}

	msg.connection_id = conn_id;
	msg.dir_mask = dir_mask;
	msg.len = len;
	memcpy(&msg.info, info, len);

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_TLS);
}

int kpm_send_max_pacing(int fd, __u32 id, __u32 pace)
{
	struct kpm_max_pacing msg;

	msg.id = id;
	msg.max_pacing = pace;

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_MAX_PACING);
}

int kpm_send_tcp_cc(int fd, __u32 id, char *cc_name)
{
	struct kpm_tcp_cc msg = {};

	msg.id = id;
	strncpy(msg.cc_name, cc_name, sizeof(msg.cc_name) - 1);

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_TCP_CC);
}

int kpm_send_mode(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
		  __u32 udmabuf_size_mb, __u32 num_rx_queues, __u8 validate)
{
	struct kpm_mode msg = {};

	msg.rx_mode = rx_mode;
	msg.tx_mode = tx_mode;
	msg.udmabuf_size_mb = udmabuf_size_mb;
	msg.num_rx_queues = num_rx_queues;
	msg.validate = validate;

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_MODE);
}

int kpm_send_pin_worker(int fd, __u32 id, __u32 cpu)
{
	struct kpm_pin_worker msg;

	msg.worker_id = id;
	msg.cpu = cpu;

	return kpm_send(fd, &msg.hdr, sizeof(msg), KPM_MSG_TYPE_PIN_WORKER);
}

static int kpm_reply(int fd, struct kpm_header *msg, size_t size,
		     struct kpm_header *req)
{
	return __kpm_send(fd, msg, size, req->id, req->type | KPM_MSG_REPLY);
}

void kpm_reply_error(int fd, struct kpm_header *hdr, __u16 error)
{
	struct kpm_reply_error msg;

	msg.type = hdr->type;
	msg.error = error;

	__kpm_send(fd, &msg.hdr, sizeof(msg), hdr->id, KPM_MSG_TYPE_ERROR);
}

int kpm_reply_empty(int fd, struct kpm_header *hdr)
{
	struct kpm_header msg;

	return kpm_reply(fd, &msg, sizeof(msg), hdr);
}

int kpm_reply_u16(int fd, struct kpm_header *hdr, __u16 arg)
{
	struct __kpm_generic_u16 msg;

	msg.val = arg;
	memset(&msg.pad, 0, sizeof(msg.pad));

	return kpm_reply(fd, &msg.hdr, sizeof(msg), hdr);
}

int kpm_reply_u32(int fd, struct kpm_header *hdr, __u32 arg)
{
	struct __kpm_generic_u32 msg;

	msg.val = arg;

	return kpm_reply(fd, &msg.hdr, sizeof(msg), hdr);
}

int kpm_reply_acceptor(int fd, struct kpm_header *hdr,
		       struct sockaddr_in6 *addr, socklen_t len)
{
	struct kpm_tcp_acceptor_reply msg;

	memcpy(&msg.addr, addr, len);
	msg.len = len;

	return kpm_reply(fd, &msg.hdr, sizeof(msg), hdr);
}

int kpm_reply_connect(int fd, struct kpm_header *hdr,
		      __u32 local_id, __u32 local_cpu, __u16 local_port,
		      __u32 remote_id, __u32 remote_cpu, __u16 remote_port)
{
	struct kpm_connect_reply msg = {};

	msg.local.id = local_id;
	msg.local.cpu = local_cpu;
	msg.local.port = local_port;
	msg.remote.id = remote_id;
	msg.remote.cpu = remote_cpu;
	msg.remote.port = remote_port;

	return kpm_reply(fd, &msg.hdr, sizeof(msg), hdr);
}

int kpm_xchg_hello(int fd, unsigned int *ncpus)
{
	struct kpm_hello hello;
	struct kpm_hello *rcv;

	hello.version = proto_ver;
	hello.n_cpus = get_nprocs();

	if (kpm_send(fd, &hello.hdr, sizeof(hello), KPM_MSG_TYPE_HELLO) < 0) {
		warnx("Failed to send hello");
		return -1;
	}

	rcv = kpm_receive(fd);
	if (!rcv)
		return -1;

	if (!kpm_good_req(rcv, KPM_MSG_TYPE_HELLO)) {
		warnx("Bad hello msg");
		goto err_free;
	}
	if (rcv->version != proto_ver) {
		warnx("Bad PROTO version");
		goto err_free;
	}

	if (ncpus)
		*ncpus = rcv->n_cpus;
	free(rcv);

	return 0;

err_free:
	free(rcv);
	return -1;
}

int kpm_req_tcp_sock(int fd, struct sockaddr_in6 *addr, socklen_t *len)
{
	struct kpm_tcp_acceptor_reply *repl;
	struct kpm_header hdr;
	int id;

	id = kpm_send(fd, &hdr, sizeof(hdr), KPM_MSG_TYPE_OPEN_TCP_ACCEPTOR);
	if (id < 0) {
		warnx("Failed to request TCP sock");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to request TCP sock - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_OPEN_TCP_ACCEPTOR, id)) {
		warnx("Failed to request TCP sock - unexpected reply");
		free(repl);
		return -1;
	}

	if (*len < repl->len) {
		warnx("Failed to request TCP sock - req space small");
		free(repl);
		return -1;
	}

	memcpy(addr, &repl->addr, repl->len);
	*len = repl->len;
	free(repl);
	return 0;
}

int kpm_req_end_test(int fd, __u32 test_id)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_u32(fd, KPM_MSG_TYPE_END_TEST, test_id);
	if (id < 0) {
		warnx("Failed to end test");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to end test - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_END_TEST, id)) {
		warnx("Failed to end test - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}

int
kpm_req_tls(int fd, __u32 conn_id, __u32 dir_mask, void *info, socklen_t len)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_tls(fd, conn_id, dir_mask, info, len);
	if (id < 0) {
		warnx("Failed to start TLS");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to start TLS - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_TLS, id)) {
		warnx("Failed to start TLS - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}

int
kpm_req_pacing(int fd, __u32 conn_id, __u32 max_pace)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_max_pacing(fd, conn_id, max_pace);
	if (id < 0) {
		warnx("Failed to request pacing");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to request pacing - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_MAX_PACING, id)) {
		warnx("Failed to request pacing - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}

int
kpm_req_tcp_cc(int fd, __u32 conn_id, char *cc_name)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_tcp_cc(fd, conn_id, cc_name);
	if (id < 0) {
		warnx("Failed to request TCP cong control");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to request TCP cong control - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_TCP_CC, id)) {
		warnx("Failed to request TCP cong control - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}

int
kpm_req_mode(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode,
	     __u32 udmabuf_size_mb, __u32 num_rx_queues, __u8 validate)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_mode(fd, rx_mode, tx_mode, udmabuf_size_mb, num_rx_queues, validate);
	if (id < 0) {
		warnx("Failed to request mode");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to request mode - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_MODE, id)) {
		warnx("Failed to request mode - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}

int kpm_req_disconnect(int fd, __u32 connection_id)
{
	struct kpm_empty *repl;
	int id;

	id = kpm_send_u32(fd, KPM_MSG_TYPE_DISCONNECT, connection_id);
	if (id < 0) {
		warnx("Failed to end connection");
		return id;
	}

	repl = kpm_receive(fd);
	if (!repl) {
		warnx("Failed to end connection - no response");
		return -1;
	}

	if (!kpm_good_reply(repl, KPM_MSG_TYPE_DISCONNECT, id)) {
		warnx("Failed to end connection - bad reply");
		free(repl);
		return -1;
	}

	free(repl);
	return 0;
}
