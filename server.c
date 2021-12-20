// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <ccan/err/err.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/list/list.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>

#include "server.h"

int verbose;

static struct {
	char *service;
	bool server;
} opt = {
	.server		= true,
	.service	= "18323",
};

static const struct opt_table opts[] = {
	OPT_WITHOUT_ARG("--no-daemon", opt_set_invbool, &opt.server,
			"Don't start a daemon"),
 	OPT_WITH_ARG("--port|-p <arg>", opt_set_charp, opt_show_charp,
		     &opt.service, "Set control port/service to listen on"),
 	OPT_WITHOUT_ARG("--verbose|-v", opt_inc_intval, &verbose,
			"Verbose mode (can be specified more than once)"),
 	OPT_WITHOUT_ARG("--usage|--help|-h", opt_usage_and_exit,
 			"kpeft server",	"Show this help message"),
 	OPT_ENDTABLE
};

static volatile int chld;

static void chld_sig_handler(int sig)
{
	chld = 1;
}

static struct list_head sessions = LIST_HEAD_INIT(sessions);

static void server_session_add(struct server_session *ses)
{
	list_add(&sessions, &ses->sessions);
}

static void server_session_del(pid_t pid)
{
	struct server_session *ses = NULL;

	list_for_each(&sessions, ses, sessions) {
		if (ses->pid == pid)
			break;
	}
	if (!ses || ses->pid != pid)
		return;

	list_del(&ses->sessions);
	free(ses);
}

static void server_reap_sessions(void)
{
	if (!chld)
		return;


	while (true) {
		int status;
		pid_t pid;

		chld = 0;
		pid = waitpid(-1, &status, WNOHANG);
		if (pid < 1)
			break;
		server_session_del(pid);
	}
}

int main(int argc, char *argv[])
{
	int fds[2], i, num_fds, max_fd;
	struct addrinfo *addr;

	opt_register_table(opts, NULL);
	if (!opt_parse(&argc, argv, opt_log_stderr))
		exit(1);

	err_set_progname(argv[0]);

	if (opt.server && daemonize())
		err(1, "can't daemonize");

	addr = net_server_lookup(opt.service, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to bind to");

	num_fds = net_bind(addr, fds);
	freeaddrinfo(addr);
	if (num_fds < 1)
		err(1, "Failed to listen");

	max_fd = num_fds == 1 || fds[0] > fds[1] ? fds[0] : fds[1];

	signal(SIGCHLD, chld_sig_handler);

	while (true) {
		struct sockaddr_in6 sockaddr;
		struct server_session *ses;
		struct timeval tv;
		socklen_t addrlen;
		int cfd, fd, ret;
		fd_set rfds;

		FD_ZERO(&rfds);
		for (i = 0; i < num_fds; i++)
			FD_SET(fds[i], &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR && chld)
				goto reap_child;
			err(2, "Failed to select");
		} else if (!ret) {
			continue;
		}

		if (FD_ISSET(fds[0], &rfds))
			fd = fds[0];
		else if (num_fds > 1 && FD_ISSET(fds[1], &rfds))
			fd = fds[1];
		else
			errx(3, "Failed to find fd");

		addrlen = sizeof(sockaddr);
		cfd = accept(fd, (void *)&sockaddr, &addrlen);
		if (cfd < 0) {
			warn("Failed to accept");
			continue;
		}

		ses = server_session_spawn(cfd, &sockaddr, &addrlen);
		if (ses)
			server_session_add(ses);
reap_child:
		server_reap_sessions();
	}

	return 0;
}
