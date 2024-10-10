// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <ccan/err/err.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/list/list.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>

#include "server.h"
#include "proto_dbg.h"

int verbose = 3;

static struct {
	char *addr;
	char *service;
	char *pid_file;
	bool kill;
	bool server;
} opt = {
	.server		= true,
	.service	= "18323",
	.pid_file	= "/tmp/kperf.pid",
};

static const struct opt_table opts[] = {
	OPT_WITH_ARG("--addr|-a <arg>", opt_set_charp, opt_show_charp,
		     &opt.addr, "Bind to specific control address"),
 	OPT_WITH_ARG("--port|-p <arg>", opt_set_charp, opt_show_charp,
		     &opt.service, "Set control port/service to listen on"),
	OPT_WITHOUT_ARG("--no-daemon", opt_set_invbool, &opt.server,
			"Don't start a daemon"),
	OPT_WITH_ARG("--pid-file <arg>", opt_set_charp, opt_show_charp,
		     &opt.pid_file, "Set daemon identity / pid file"),
	OPT_WITHOUT_ARG("--kill", opt_set_bool, &opt.kill, "Stop the daemon"),
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

static void kill_old_daemon(void)
{
	char buf[10];
	ssize_t n;
	pid_t pid;
	int fd;

	fd = open(opt.pid_file, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return;
		err(2, "Failed to open PID file");
	}

	n = read(fd, buf, sizeof(buf));
	if (n < 0)
		err(2, "Failed to read PID file");
	if (!n || n == sizeof(buf))
		errx(2, "Bad pid file len - %zd", n);
	buf[n] = 0;
	close(fd);

	pid = atoi(buf);

	if (kill(pid, SIGKILL))
		if (errno != ESRCH)
			err(2, "Can't kill the old daemon");

	if (unlink(opt.pid_file))
		err(2, "Failed to remove pid file");
}

static void server_daemonize(void)
{
	char buf[10];
	ssize_t n;
	int fd;

	fd = open(opt.pid_file, O_WRONLY | O_CREAT | O_EXCL, 00660);
	if (fd < 0)
		err(3, "Failed to create PID file");

	if (!daemonize())
		err(1, "can't daemonize");

	n = snprintf(buf, sizeof(buf), "%d", getpid());
	if (!n || n == sizeof(buf))
		errx(3, "Bad pid file len - %zd", n);

	if (write(fd, buf, n) != n)
		err(3, "Short write to pid file");
	close(fd);
}

/* same as net_server_lookup but accepts the node argument */
static struct addrinfo *net_server_lookup_node(const char *node,
					       const char *service,
					       int family,
					       int socktype)
{
	struct addrinfo *res, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	if (getaddrinfo(node, service, &hints, &res) != 0)
		return NULL;

	return res;
}

static void log_address(const char *format, struct sockaddr_in6 *sin6)
{
	struct sockaddr_in *sin = (void *)sin6;
	char buf[256];

	if (sin6->sin6_family == AF_INET6)
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
	else
		inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));

	kpm_info(format, buf);
}

static void print_listener(int *fds, int num_fds)
{
	struct sockaddr_in6 sin6;
	socklen_t sa_len;
	int ret;
	int i;

	for (i = 0; i < num_fds; i++) {
		sa_len = sizeof(sin6);
		ret = getsockname(fds[i], (struct sockaddr *)&sin6, &sa_len);
		if (ret != 0)
			err(1, "Failed to look up address for fd %d", fds[i]);
		log_address("Bound to %s", &sin6);
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

	if (opt.server || opt.kill)
		kill_old_daemon();
	if (opt.kill)
		return 0;

	if (opt.server)
		server_daemonize();

	addr = net_server_lookup_node(opt.addr, opt.service, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to bind to");

	num_fds = net_bind(addr, fds);
	freeaddrinfo(addr);
	if (num_fds < 1)
		err(1, "Failed to listen");
	if (opt.addr)
		print_listener(fds, num_fds);

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

		if (opt.addr)
			log_address("Accepted %s", &sockaddr);
		ses = server_session_spawn(cfd, &sockaddr, &addrlen);
		if (ses)
			server_session_add(ses);
reap_child:
		server_reap_sessions();
	}

	return 0;
}
