// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <signal.h>
#include <stddef.h>
#include <sys/signalfd.h>

#include <ccan/err/err.h>

#include "signals.h"

static void term_sigset(sigset_t *set)
{
	sigemptyset(set);
	sigaddset(set, SIGTERM);
	sigaddset(set, SIGINT);
}

void block_term_signals(sigset_t *old)
{
	sigset_t set;

	term_sigset(&set);
	if (sigprocmask(SIG_BLOCK, &set, old))
		err(2, "Failed to block signals");
}

void trap_term_signals(void (*handler)(int sig))
{
	signal(SIGTERM, handler);
	signal(SIGINT, handler);
}

void reset_term_signals(void)
{
	sigset_t set;

	trap_term_signals(SIG_DFL);
	term_sigset(&set);
	if (sigprocmask(SIG_UNBLOCK, &set, NULL))
		err(2, "Failed to unblock signals");
}

int term_signals_fd(void)
{
	sigset_t set;
	int fd;

	block_term_signals(NULL);
	term_sigset(&set);
	fd = signalfd(-1, &set, SFD_CLOEXEC);
	if (fd < 0)
		err(2, "Failed to create signalfd");
	return fd;
}
