/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef EPOLL_H
#define EPOLL_H 1

#include "worker.h"

void worker_epoll_init(struct worker_state *state);

#endif /* EPOLL_H */
