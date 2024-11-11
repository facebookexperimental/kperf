/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef SERVER_H
#define SERVER_H 1

#include <netdb.h>
#include <sys/types.h>

#include <ccan/compiler/compiler.h>
#include <ccan/list/list.h>

#include "proto.h"

struct server_session {
	int cfd;
	pid_t pid;
	struct list_node sessions;
};

struct server_session *
server_session_spawn(int fd, struct sockaddr_in6 *addr, socklen_t *addrlen);

void NORETURN pworker_main(int fd, enum kpm_rx_mode rx_mode, enum kpm_tx_mode tx_mode);

#endif /* SERVER_H */
