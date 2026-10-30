/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef SIGNALS_H
#define SIGNALS_H 1

#include <signal.h>

void block_term_signals(sigset_t *old);
void trap_term_signals(void (*handler)(int sig));
void reset_term_signals(void);
int term_signals_fd(void);

#endif /* SIGNALS_H */
