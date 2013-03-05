/*
 * sydbox/sydbox.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/queue.h>
#include <getopt.h>
#include "asyd.h"
#include "macro.h"
#include "file.h"
#include "pathlookup.h"
#include "proc.h"
#include "log.h"
#include "util.h"
#ifdef WANT_SECCOMP
#include "seccomp.h"
#endif

#if PINK_HAVE_SEIZE
static int post_attach_sigstop = SYD_IGNORE_ONE_SIGSTOP;
# define syd_use_seize (post_attach_sigstop == 0)
#else
# define post_attach_sigstop SYD_IGNORE_ONE_SIGSTOP
# define syd_use_seize 0
#endif

#ifndef NR_OPEN
# define NR_OPEN 1024
#endif

sydbox_t *sydbox;
static unsigned os_release;
static volatile sig_atomic_t interrupted;
static bool interactive;
static sigset_t empty_set, blocked_set;

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION);
	printf(" (pinktrace-%d.%d.%d",
	       PINKTRACE_VERSION_MAJOR,
	       PINKTRACE_VERSION_MINOR,
	       PINKTRACE_VERSION_MICRO);

	if (STRLEN_LITERAL(PINKTRACE_VERSION_SUFFIX) > 0)
		fputs(PINKTRACE_VERSION_SUFFIX, stdout);
	if (STRLEN_LITERAL(PINKTRACE_GIT_HEAD) > 0)
		printf(" git:%s", PINKTRACE_GIT_HEAD);
	puts(")");

	printf("Options:");
#ifdef WANT_SECCOMP
	printf(" seccomp:yes");
#else
	printf(" seccomp:no");
#endif
	printf(" ipv6:%s", PINK_HAVE_IPV6 ? "yes" : "no");
	printf(" netlink:%s", PINK_HAVE_NETLINK ? "yes" : "no");
	fputc('\n', stdout);
}

PINK_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- ptrace based sandbox\n\
usage: "PACKAGE" [-hv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n\
\n\
Hey you, out there beyond the wall,\n\
Breaking bottles in the hall,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

static void kill_save_errno(pid_t pid, int sig)
{
	int saved_errno = errno;

	(void) kill(pid, sig);
	errno = saved_errno;
}

static syd_proc_t *add_proc(pid_t pid, short flags)
{
	int r;
	syd_proc_t *newproc;

	newproc = calloc(1, sizeof(syd_proc_t));
	if (!newproc)
		return NULL;

	if ((r = pink_process_alloc(pid, &newproc->pink)) < 0) {
		errno = -r;
		return NULL;
	}
	newproc->ppid = 0;
	newproc->trace_step = SYD_STEP_NOT_SET;
	newproc->flags = SYD_STARTUP | flags;

	SYD_INSERT_HEAD(newproc);
	return newproc;
}

static syd_proc_t *add_proc_or_kill(pid_t pid, short flags)
{
	syd_proc_t *newproc;

	newproc = add_proc(pid, flags);
	if (!newproc) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return newproc;
}

void clear_proc(syd_proc_t *p)
{
	if (!p)
		return;
	if (p->flags & SYD_IGNORE_PROCESS)
		return;

	p->sysnum = 0;
	p->sysname = NULL;
	for (unsigned i = 0; i < PINK_MAX_ARGS; i++)
		p->args[i] = 0;
	p->subcall = 0;
	p->retval = 0;
	p->flags &= ~SYD_DENY_SYSCALL;
	p->flags &= ~SYD_STOP_AT_SYSEXIT;

	if (p->savebind)
		free_sockinfo(p->savebind);
	p->savebind = NULL;
}

void ignore_proc(syd_proc_t *p)
{
	pid_t pid;

	if (!p)
		return;
	if (p->flags & SYD_IGNORE_PROCESS)
		return;
	pid = GET_PID(p);

	if (p->abspath)
		free(p->abspath);
	if (p->cwd)
		free(p->cwd);
	if (p->comm)
		free(p->comm);
	if (p->pink)
		pink_process_free(p->pink);
	if (p->savebind)
		free_sockinfo(p->savebind);

	if (p->sockmap) {
		/* Free the fd -> address mappings */
		for (int i = 0; i < p->sockmap->size; i++) {
			ht_int64_node_t *node = HT_NODE(p->sockmap, p->sockmap->nodes, i);
			if (node->data)
				free_sockinfo(node->data);
		}
		hashtable_destroy(p->sockmap);
	}

	/* Free the sandbox */
	free_sandbox(&p->config);

	p->flags |= SYD_IGNORE_PROCESS;
	log_context(NULL);
	log_trace("ignored process %u", pid);
}

void remove_proc(syd_proc_t *p)
{
	if (!p)
		return;
	ignore_proc(p);
	SYD_REMOVE_PROCESS(p);
	free(p);
}

syd_proc_t *lookup_proc(pid_t pid)
{
	syd_proc_t *proc;

	SYD_FOREACH_PROCESS(proc) {
		if (pid == GET_PID(proc))
			return proc;
	}
	return NULL;
}

static void interrupt(int sig)
{
	interrupted = sig;
}

static unsigned get_os_release(void)
{
	unsigned rel;
	const char *p;
	struct utsname u;

	if (uname(&u) < 0)
		die_errno("uname");
	/* u.release has this form: "3.2.9[-some-garbage]" */
	rel = 0;
	p = u.release;
	for (;;) {
		if (!(*p >= '0' && *p <= '9'))
			die("Bad OS release string: '%s'", u.release);
		/* Note: this open-codes KERNEL_VERSION(): */
		rel = (rel << 8) | atoi(p);
		if (rel >= KERNEL_VERSION(1,0,0))
			break;
		while (*p >= '0' && *p <= '9')
			p++;
		if (*p != '.') {
			if (rel >= KERNEL_VERSION(0,1,0)) {
				/* "X.Y-something" means "X.Y.0" */
				rel <<= 8;
				break;
			}
			die("Bad OS release string: '%s'", u.release);
		}
		p++;
	}

	return rel;
}

static bool dump_one_process(syd_proc_t *current, bool verbose)
{
	int r;
	const char *CG, *CB, *CN, *CI, *CE; /* good, bad, important, normal end */
	struct proc_statinfo info;

	pid_t pid = GET_PID(current);
	short abi = GET_ABI(current);
	pid_t ppid = current->ppid;
	struct snode *node;
	struct sockmatch *match;

	if (isatty(STDERR_FILENO)) {
		CG = ANSI_GREEN;
		CB = ANSI_DARK_MAGENTA;
		CI = ANSI_CYAN;
		CN = ANSI_YELLOW;
		CE = ANSI_NORMAL;
	} else {
		CG = CB = CI = CN = CE = "";
	}

	fprintf(stderr, "%s-- Information on Process ID: %u%s\n", CG, pid, CE);
	fprintf(stderr, "\t%sParent ID: %u%s\n", CN, ppid > 0 ? ppid : 0, CE);
	fprintf(stderr, "\t%sComm: `%s'%s\n", CN, current->comm, CE);
	fprintf(stderr, "\t%sCwd: `%s'%s\n", CN, current->cwd, CE);
	fprintf(stderr, "\t%sSyscall: {no:%lu abi:%d name:%s}%s\n", CN,
			current->sysnum, abi, current->sysname, CE);
	fprintf(stderr, "\t%sFlags: ", CN);
	r = 0;
	if (current->flags & SYD_SYDBOX_CHILD) {
		fprintf(stderr, "%sSYDBOX_CHILD", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IGNORE_PROCESS) {
		fprintf(stderr, "%sIGNORE_PROCESS", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_STARTUP) {
		fprintf(stderr, "STARTUP");
		r = 1;
	}
	if (current->flags & SYD_IGNORE_ONE_SIGSTOP) {
		fprintf(stderr, "%sIGNORE_ONE_SIGSTOP", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_INHERIT_DONE) {
		fprintf(stderr, "%sINHERIT_DONE", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IN_SYSCALL) {
		fprintf(stderr, "%sIN_SYSCALL", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_DENY_SYSCALL) {
		fprintf(stderr, "%sDENY_SYSCALL", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_STOP_AT_SYSEXIT) {
		fprintf(stderr, "%sSTOP_AT_SYSEXIT", (r == 1) ? "|" : "");
		r = 1;
	}
	fprintf(stderr, "%s\n", CN);

	if ((r = proc_stat(pid, &info)) < 0) {
		fprintf(stderr, "%sproc_stat failed (errno:%d %s)%s\n",
			CB, errno, strerror(errno), CE);
	} else {
		fprintf(stderr, "\t%sproc: pid=%d ppid=%d pgrp=%d%s\n",
			CI,
			info.pid, info.ppid, info.pgrp,
			CE);
		fprintf(stderr, "\t%sproc: comm=`%s' state=`%c'%s\n",
			CI,
			info.comm, info.state,
			CE);
		fprintf(stderr, "\t%sproc: session=%d tty_nr=%d tpgid=%d%s\n",
			CI,
			info.session, info.tty_nr, info.tpgid,
			CE);
		fprintf(stderr, "\t%sproc: nice=%ld num_threads=%ld%s\n",
			CI,
			info.nice, info.num_threads,
			CE);
	}

	if (!verbose)
		return true;

	fprintf(stderr, "\t%sSandbox: {exec:%s read:%s write:%s sock:%s}%s\n",
		CN,
		sandbox_mode_to_string(current->config.sandbox_exec),
		sandbox_mode_to_string(current->config.sandbox_read),
		sandbox_mode_to_string(current->config.sandbox_write),
		sandbox_mode_to_string(current->config.sandbox_network),
		CE);
	fprintf(stderr, "\t%sMagic Lock: %s%s\n", CN, lock_state_to_string(current->config.magic_lock), CE);
	fprintf(stderr, "\t%sExec Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &current->config.whitelist_exec, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &current->config.whitelist_read, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &current->config.whitelist_write, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	SLIST_FOREACH(node, &current->config.whitelist_network_bind, up) {
		match = node->data;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	SLIST_FOREACH(node, &current->config.whitelist_network_connect, up) {
		match = node->data;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}

	return true;
}

static void sig_usr(int signo)
{
	bool complete_dump;
	unsigned count;
	syd_proc_t *node;

	if (!sydbox)
		return;

	complete_dump= !!(signo == SIGUSR2);

	fprintf(stderr, "\nsydbox: Received SIGUSR%s, dumping %sprocess tree\n",
		complete_dump ? "2" : "1",
		complete_dump ? "complete " : "");
	count = 0;
	SYD_FOREACH_PROCESS(node) {
		dump_one_process(node, complete_dump);
		count++;
	}
	fprintf(stderr, "Tracing %u process%s\n", count, count > 1 ? "es" : "");
}

static void init_early(void)
{
	assert(!sydbox);

	os_release = get_os_release();
	sydbox = xmalloc(sizeof(sydbox_t));
	sydbox->violation = false;
	sydbox->wait_execve = false;
	sydbox->exit_code = EXIT_SUCCESS;
	sydbox->nprocs = 0;
	SLIST_INIT(&sydbox->proctab);
	config_init();
	log_init(NULL);
	log_abort_func(abort_all);
}

static void init_signals(void)
{
	struct sigaction sa;

	sigemptyset(&empty_set);
	sigemptyset(&blocked_set);

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	int r;
	enum trace_interrupt intr = sydbox->config.trace_interrupt;
#define x_sigaction(sig, act, oldact) \
	do { \
		r = sigaction((sig), (act), (oldact)); \
		if (r < 0) \
			die_errno("sigaction"); \
	} while (0)

	x_sigaction(SIGTTOU, &sa, NULL); /* SIG_IGN */
	x_sigaction(SIGTTIN, &sa, NULL); /* SIG_IGN */

	if (intr != TRACE_INTR_ANYWHERE) {
		if (intr == TRACE_INTR_BLOCK_TSTP_TOO)
			x_sigaction(SIGTSTP, &sa, NULL); /* SIG_IGN */

		if (intr == TRACE_INTR_WHILE_WAIT) {
			sigaddset(&blocked_set, SIGHUP);
			sigaddset(&blocked_set, SIGINT);
			sigaddset(&blocked_set, SIGQUIT);
			sigaddset(&blocked_set, SIGPIPE);
			sigaddset(&blocked_set, SIGTERM);
			sa.sa_handler = interrupt;
			interactive = true;
		}
		/* SIG_IGN, or set handler for these */
		x_sigaction(SIGHUP, &sa, NULL);
		x_sigaction(SIGINT, &sa, NULL);
		x_sigaction(SIGQUIT, &sa, NULL);
		x_sigaction(SIGPIPE, &sa, NULL);
		x_sigaction(SIGTERM, &sa, NULL);
	}
#undef x_sigaction
	signal(SIGUSR1, sig_usr);
	signal(SIGUSR2, sig_usr);
}

static void cleanup(void)
{
	struct snode *node;

	assert(sydbox);

	/* Free the global configuration */
	free_sandbox(&sydbox->config.child);

	SLIST_FREE_ALL(node, &sydbox->config.exec_kill_if_match, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.exec_resume_if_match, up, free);

	SLIST_FREE_ALL(node, &sydbox->config.filter_exec, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_read, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_write, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_network, up, free_sockmatch);

	free(sydbox->program_invocation_name);
	free(sydbox);
	sydbox = NULL;

	systable_free();
	log_close();
}

static void startup_child(char **argv)
{
	int r;
	char *pathname;
	pid_t pid = 0;

	r = path_lookup(argv[0], &pathname);
	if (r < 0) {
		errno = -r;
		die_errno("can't exec `%s'", argv[0]);
	}

	pid = fork();
	if (pid < 0)
		die_errno("can't fork");
	else if (pid == 0) {
		int r;
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp) {
			if ((r = seccomp_init()) < 0) {
				fprintf(stderr,
					"seccomp_init failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}

			if ((r = sysinit_seccomp()) < 0) {
				fprintf(stderr,
					"seccomp_apply failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}
#endif
		pid = getpid();
		if (!syd_use_seize) {
			if ((r = pink_trace_me() < 0)) {
				fprintf(stderr,
					"ptrace(PTRACE_TRACEME) failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}

		kill(pid, SIGSTOP);

		execv(pathname, argv);
		fprintf(stderr, "execv failed (errno:%d %s)\n", errno, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	free(pathname);
#if PINK_HAVE_SEIZE
	if (syd_use_seize) {
		/* Wait until child stopped itself */
		int status;
		while (waitpid(pid, &status, WSTOPPED) < 0) {
			if (errno == EINTR)
				continue;
			die_errno("waitpid");
		}
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
			kill_save_errno(pid, SIGKILL);
			die_errno("Unexpected wait status %x", status);
		}
		if ((r = pink_trace_seize(pid, sydbox->trace_options)) < 0 ||
		    (r = pink_trace_interrupt(pid) < 0)) {
			kill_save_errno(pid, SIGKILL);
			die_errno("Can't attach to %u", pid);
		}
		kill(pid, SIGCONT);
	}
#endif
	add_proc_or_kill(pid, SYD_SYDBOX_CHILD | post_attach_sigstop);
	sydbox->wait_execve = true;
}

static int handle_interrupt(int fatal_sig)
{
	if (!fatal_sig)
		fatal_sig = SIGTERM;

	abort_all(fatal_sig);
	return 128 + fatal_sig;
}

static int ptrace_error(syd_proc_t *current, const char *req, int err_no)
{
	if (err_no != ESRCH) {
		err_fatal(err_no, "ptrace(%s, %u) failed", req, GET_PID(current));
		return panic(current);
	}
	ignore_proc(current);
	return -ESRCH;
}

static int ptrace_step(syd_proc_t *current, int sig)
{
	int r;
	pid_t pid;
	enum syd_step step;
	const char *msg;

	pid = GET_PID(current);
	step = current->trace_step == SYD_STEP_NOT_SET
	       ? sydbox->trace_step
	       : current->trace_step;

	switch (step) {
	case SYD_STEP_SYSCALL:
		r = pink_trace_syscall(pid, sig);
		msg = "PTRACE_SYSCALL";
		break;
	case SYD_STEP_RESUME:
		r = pink_trace_resume(pid, sig);
		msg = "PTRACE_CONT";
		break;
	default:
		assert_not_reached();
	}

	return (r < 0) ? ptrace_error(current, msg, -r) : r;
}

static void inherit_sandbox(syd_proc_t *current, syd_proc_t *parent)
{
	char *comm;
	char *cwd;
	struct snode *node, *newnode;
	sandbox_t *inherit;

	if (current->flags & SYD_INHERIT_DONE) {
		log_trace("inherited sandbox already, skipping");
		return;
	}

	if (sydchild(current)) {
		comm = xstrdup(sydbox->program_invocation_name);
		cwd = xgetcwd();
		inherit = &sydbox->config.child;
	} else {
		if (parent->flags & SYD_IGNORE_PROCESS) {
			/* parent is ignored, ignore the child too */
			comm = cwd = NULL;
			current->comm = current->cwd = NULL;
			current->flags |= SYD_IGNORE_PROCESS;
			goto out;
		}
		comm = xstrdup(parent->comm);
		cwd = xstrdup(parent->cwd);
		inherit = &parent->config;
	}

	/* Copy the configuration */
	current->comm = comm;
	current->cwd = cwd;
	current->config.sandbox_exec = inherit->sandbox_exec;
	current->config.sandbox_read = inherit->sandbox_read;
	current->config.sandbox_write = inherit->sandbox_write;
	current->config.sandbox_network = inherit->sandbox_network;
	current->config.magic_lock = inherit->magic_lock;

	/* Copy the lists  */
	SLIST_COPY_ALL(node, &inherit->whitelist_exec, up,
		       &current->config.whitelist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_read, up,
		       &current->config.whitelist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_write, up,
		       &current->config.whitelist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_network_bind, up,
		       &current->config.whitelist_network_bind, newnode,
		       sockmatch_xdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_network_connect, up,
		       &current->config.whitelist_network_connect, newnode,
		       sockmatch_xdup);

	SLIST_COPY_ALL(node, &inherit->blacklist_exec, up,
		       &current->config.blacklist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_read, up,
		       &current->config.blacklist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_write, up,
		       &current->config.blacklist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_bind, up,
		       &current->config.blacklist_network_bind, newnode,
		       sockmatch_xdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_connect, up,
		       &current->config.blacklist_network_connect, newnode,
		       sockmatch_xdup);

	/* Create the fd -> address hash table */
	current->sockmap = hashtable_create(NR_OPEN, 1);
	if (current->sockmap == NULL)
		die_errno("hashtable_create");

	if (sydbox->config.whitelist_per_process_directories) {
		char magic[sizeof("/proc/%u/***") + sizeof(int)*3 + /*paranoia:*/16];
		sprintf(magic, "/proc/%u/***", GET_PID(current));
		magic_append_whitelist_read(magic, current);
		magic_append_whitelist_write(magic, current);
	}
out:
	current->flags |= SYD_INHERIT_DONE;
	log_trace("initialised (parent:%u)", parent ? GET_PID(parent) : 0);
}

static int event_startup(syd_proc_t *current)
{
	int r;

	if (!syd_use_seize) {
		if ((r = syd_trace_setup(current)) < 0)
			return ptrace_error(current, "PTRACE_SETOPTIONS", -r);
	}
	current->flags &= ~SYD_STARTUP;
	return 0;
}

static int event_init(syd_proc_t *current)
{
	int r;
	pid_t pid;
	pid_t ppid;
	syd_proc_t *parent;

	if (sydchild(current)) {
		inherit_sandbox(current, NULL);
		return 0;
	} else if (hasparent(current)) {
		parent = lookup_proc(current->ppid);
		if (!parent)
			die("Unknown parent pid: %u", current->ppid);
		inherit_sandbox(current, parent);
		return 0;
	} else if (current->flags & SYD_STARTUP) {
		log_trace("[event_init]: waiting for parent");
		return 0;
	}

	pid = GET_PID(current);
	if ((r = proc_tgid(pid, &ppid)) < 0) {
		err_warning(-r, "PANIC: failed to read /proc/%u/status", pid);
		return panic(current);
	}
	if (ppid <= 1) {
		log_warning("parent died before we could inherit sandbox");
		log_warning("inheriting default sandbox");
		inherit_sandbox(current, NULL);
		return 0;
	} else if (!(parent = lookup_proc(ppid))) {
		log_warning("PANIC: unknown parent:%u of pid: %u", ppid, pid);
		return panic(current);
	}

	current->ppid = ppid;
	inherit_sandbox(current, parent);
	return 0;
}

static int event_exec(syd_proc_t *current)
{
	int e, r;
	char *comm;
	const char *match;

	if (sydbox->wait_execve) {
		log_info("[wait_execve]: execve() ptrace trap");
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp) {
			log_info("[wait_execve]: sandboxing started");
			sydbox->wait_execve = false;
		}
#endif
		return 0;
	}


	if (current->flags & SYD_IGNORE_PROCESS)
		return 0;

	if (current->config.magic_lock == LOCK_PENDING) {
		log_magic("locked magic commands");
		current->config.magic_lock = LOCK_SET;
	}

	if (!current->abspath) /* nothing left to do */
		return 0;

	/* kill_if_match and resume_if_match */
	r = 0;
	if (box_match_path(&sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		log_warning("kill_if_match pattern=`%s' matches execve path=`%s'",
			    match, current->abspath);
		log_warning("killing process");
		syd_trace_kill(current, SIGKILL);
		ignore_proc(current);
		return -ESRCH;
	} else if (box_match_path(&sydbox->config.exec_resume_if_match,
				  current->abspath, &match)) {
		log_warning("resume_if_match pattern=`%s' matches execve path=`%s'",
			    match, current->abspath);
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp) {
			/*
			 * Careful! Detaching here would cause the untraced
			 * process' observed system calls to return -ENOSYS.
			 */
			log_warning("cannot detach due to seccomp, ignoring");
			ignore_proc(current);
			return -ECHILD;
		}
#endif
		log_warning("detaching from process");
		syd_trace_detach(current, 0);
		ignore_proc(current);
		return -ESRCH;
	} else {
		log_match("execve path=`%s' does not match if_match patterns",
			  current->abspath);
	}

	/* Update process name */
	if ((e = basename_alloc(current->abspath, &comm))) {
		err_warning(-e, "updating process name failed");
		comm = xstrdup("???");
	} else if (strcmp(comm, current->comm)) {
		log_info("updating process name to `%s' due to execve()", comm);
	}

	if (current->comm)
		free(current->comm);
	current->comm = comm;

	free(current->abspath);
	current->abspath = NULL;

	return r;
}

static int event_fork(syd_proc_t *current)
{
	int r;
	pid_t pid = GET_PID(current);
	unsigned long cpid;
	syd_proc_t *child;

	if ((r = syd_trace_geteventmsg(current, &cpid)) < 0)
		return r;

	child = lookup_proc(cpid);
	if (!child)
		child = add_proc_or_kill(cpid, post_attach_sigstop);
	else if (child->flags & SYD_INHERIT_DONE)
		return 0;

	log_trace("[event_fork]: initialising %lu", cpid);
	child->ppid = pid;
	log_context(child);
	inherit_sandbox(child, current);
	log_context(current);

	return 0;
}

static int event_syscall(syd_proc_t *current)
{
	int r = 0;

	if (sydbox->wait_execve) {
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp)
			return 0;
#endif
		if (entering(current)) {
			log_info("[wait_execve]: entering execve()");
			current->flags |= SYD_IN_SYSCALL;
		} else {
			log_info("[wait_execve]: exiting execve(), sandboxing started");
			current->flags &= ~SYD_IN_SYSCALL;
			sydbox->wait_execve = false;
		}
		return 0;
	}

	if (current->flags & SYD_IGNORE_PROCESS)
		return 0;

	if (entering(current)) {
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp &&
		    (current->flags & SYD_STOP_AT_SYSEXIT)) {
			log_trace("seccomp: skipping sysenter");
			current->flags |= SYD_IN_SYSCALL;
			return 0;
		}
#endif
		if ((r = UPDATE_REGSET(current)) < 0)
			return ptrace_error(current, "PTRACE_GETREGSET", -r);
		r = sysenter(current);
#ifdef WANT_SECCOMP
		if (sydbox->config.use_seccomp &&
		    !(current->flags & SYD_STOP_AT_SYSEXIT)) {
			log_trace("seccomp: skipping sysexit, resuming");
			current->trace_step = SYD_STEP_RESUME;
			return r;
		}
#endif
		current->flags |= SYD_IN_SYSCALL;
	} else {
		if ((r = UPDATE_REGSET(current)) < 0)
			return ptrace_error(current, "PTRACE_GETREGSET", -r);
		r = sysexit(current);
		current->flags &= ~SYD_IN_SYSCALL;
	}
	return r;
}

#ifdef WANT_SECCOMP
static int event_seccomp(syd_proc_t *current)
{
	int r;

	if (sydbox->wait_execve) {
		log_info("[wait_execve]: execve() seccomp trap");
		return 0;
	}

	if (current->flags & SYD_IGNORE_PROCESS)
		return 0;

#if 0
	if ((r = syd_trace_geteventmsg(current, &ret_data)) < 0)
		return ptrace_error(current, "PTRACE_GETEVENTMSG", -r);
#endif

	if ((r = UPDATE_REGSET(current)) < 0)
		return ptrace_error(current, "PTRACE_GETREGSET", -r);
	r = sysenter(current);
	if (current->flags & SYD_STOP_AT_SYSEXIT) {
		/* step using PTRACE_SYSCALL until we hit sysexit. */
		current->flags &= ~SYD_IN_SYSCALL;
		current->trace_step = SYD_STEP_SYSCALL;
	}
	return r;
}
#endif

static int event_exit(syd_proc_t *current, int status)
{
	int code = EXIT_FAILURE;

	if (WIFEXITED(status)) {
		code = WEXITSTATUS(status);
		log_trace("exited with code:%d (status:0x%04x)", code, status);
	} else {
		code = 128 + WTERMSIG(status);
		log_trace("terminated with signal:%d (status:0x%04x)",
			  WTERMSIG(status), status);
	}

	if (sydchild(current)) {
		sydbox->exit_code = code;
		if (!sydbox->config.exit_wait_all) {
			log_trace("aborting loop (wait_all not set)");
			remove_proc(current);
			cont_all();
			exit(sydbox->exit_code);
		}
	}
	remove_proc(current);
	return 0;
}

static int trace(void)
{
	pid_t pid;
	bool stopped;
	int r;
	int status, sig;
	int wait_errno;
	unsigned event;
	syd_proc_t *current;
#ifdef __WALL
	static int waitpid_options = __WALL;
#endif
	int syscall_trap_sig;

	syscall_trap_sig = sydbox->trace_options & PINK_TRACE_OPTION_SYSGOOD
			   ? SIGTRAP | 0x80
			   : SIGTRAP;
	while(sydbox->nprocs > 0) {
		log_context(NULL);

		if (interrupted) {
			sig = interrupted;
			return handle_interrupt(sig);
		}

		if (interactive)
			sigprocmask(SIG_SETMASK, &empty_set, NULL);
#ifdef __WALL
		pid = waitpid(-1, &status, waitpid_options);
		if (pid < 0 && (waitpid_options & __WALL) && errno == EINVAL) {
			/* this kernel does not support __WALL */
			waitpid_options &= ~__WALL;
			pid = waitpid(-1, &status, waitpid_options);
		}
		if (pid < 0 && !(waitpid_options & __WALL) && errno == ECHILD) {
			/* most likely a "cloned" process */
			pid = waitpid(-1, &status, __WCLONE);
			if (pid < 0) {
				err_fatal(errno, "wait failed");
				goto cleanup;
			}
		}
#else
		pid = waitpid(-1, &status, 0);
#endif /* __WALL */
		wait_errno = errno;
		if (interactive)
			sigprocmask(SIG_SETMASK, &blocked_set, NULL);

		if (pid < 0) {
			switch (wait_errno) {
			case EINTR:
				continue;
			case ECHILD:
				goto cleanup;
			default:
				err_fatal(wait_errno, "wait failed");
				goto cleanup;
			}
		}

		event = pink_event_decide(status);
		if (log_has_level(LOG_LEVEL_TRACE)) {
			char buf[sizeof("WIFEXITED,exitcode=%u") + sizeof(int)*3 /*paranoia:*/ + 16];
			char evbuf[sizeof(",PTRACE_EVENT_?? (%u)") + sizeof(int)*3 /*paranoia:*/ + 16];
			strcpy(buf, "???");
			if (WIFSIGNALED(status))

#ifdef WCOREDUMP
				sprintf(buf, "WIFSIGNALED,%ssig=%d|%s|",
					WCOREDUMP(status) ? "core," : "",
					WTERMSIG(status),
					pink_name_signal(WTERMSIG(status), 0));
#else
				sprintf(buf, "WIFSIGNALED,sig=%d|%s|",
					WTERMSIG(status),
					pink_name_signal(WTERMSIG(status), 0));
#endif
			if (WIFEXITED(status))
				sprintf(buf, "WIFEXITED,exitcode=%u", WEXITSTATUS(status));
			if (WIFSTOPPED(status))
				sprintf(buf, "WIFSTOPPED,sig=%d|%s|",
					WSTOPSIG(status),
					pink_name_signal(WSTOPSIG(status), 0));
#ifdef WIFCONTINUED
			if (WIFCONTINUED(status))
				strcpy(buf, "WIFCONTINUED");
#endif
			evbuf[0] = '\0';
			if (event != 0) {
				const char *e;
				e = pink_name_event(event);
				if (!e) {
					sprintf(buf, "?? (%u)", event);
					e = buf;
				}
				sprintf(evbuf, "PTRACE_EVENT_%s", e);
			}
			log_trace("[wait(0x%04x) = %u] %s%s", status, pid, buf, evbuf);
		}

		current = lookup_proc(pid);
		log_context(current);

		if (!current) {
			if (sydbox->config.follow_fork) {
				current = add_proc_or_kill(pid, post_attach_sigstop);
				log_context(current);
				log_trace("Process %u attached", pid);
			} else {
				/* This can happen if a clone call used
				 * CLONE_PTRACE itself. */
#if 0
				if (WIFSTOPPED(status))
					pink_trace_detach(pid, 0);
#endif
				die("Unknown pid: %u", pid); /* XXX */
			}
		}

		/* Under Linux, execve changes pid to thread leader's pid,
		 * and we see this changed pid on EVENT_EXEC and later,
		 * execve sysexit. Leader "disappears" without exit
		 * notification. Let user know that, drop leader's tcb,
		 * and fix up pid in execve thread's tcb.
		 * Effectively, execve thread's tcb replaces leader's tcb.
		 *
		 * BTW, leader is 'stuck undead' (doesn't report WIFEXITED
		 * on exit syscall) in multithreaded programs exactly
		 * in order to handle this case.
		 *
		 * PTRACE_GETEVENTMSG returns old pid starting from Linux 3.0.
		 * On 2.6 and earlier, it can return garbage.
		 */
		if (event == PINK_EVENT_EXEC && os_release >= KERNEL_VERSION(3,0,0)) {
			syd_proc_t *execve_thread;
			long old_tid = 0;

			if ((r = pink_trace_geteventmsg(pid, (unsigned long *) &old_tid)) < 0)
				goto dont_switch_procs;
			if (old_tid <= 0 || old_tid == pid)
				goto dont_switch_procs;
			execve_thread = lookup_proc(old_tid);
			/* It should be !NULL, but someone feels paranoid */
			if (!execve_thread)
				goto dont_switch_procs;
			log_trace("leader %lu superseded by execve in tid %u",
				  old_tid, pid);
			/* Drop leader, switch to the thread, reusing leader's tid */
			remove_proc(current);
			current = execve_thread;
			log_context(current);
			SET_PID(current, pid);
		}
dont_switch_procs:
		if (event == PINK_EVENT_EXEC) {
			r = event_exec(current);
			if (r == -ECHILD) /* process ignored */
				goto restart_tracee_with_sig_0;
			else if (r < 0) /* process dead */
				continue;
		}

		if (WIFSIGNALED(status) || WIFEXITED(status)) {
			event_exit(current, status);
			continue;
		}

		if (!WIFSTOPPED(status)) {
			log_fatal("PANIC: not stopped (status:0x%04x)", status);
			panic(current);
			continue;
		}

		if (!(current->flags & SYD_INHERIT_DONE)) {
			if ((r = event_init(current)) < 0)
				continue; /* process dead */
		}
		if (current->flags & SYD_STARTUP) {
			log_trace("SYD_STARTUP set, initialising");
			if ((r = event_startup(current)) < 0)
				continue; /* process dead */
		}

		sig = WSTOPSIG(status);

		if (event != 0) {
			/* Ptrace event */
			if (event == PINK_EVENT_FORK ||
			    event == PINK_EVENT_VFORK ||
			    event == PINK_EVENT_CLONE) {
				if ((r = event_fork(current)) < 0)
					continue; /* process dead */
			}
#if PINK_HAVE_SEIZE
			else if (event == PINK_EVENT_STOP) {
				/*
				 * PTRACE_INTERRUPT-stop or group-stop.
				 * PTRACE_INTERRUPT-stop has sig == SIGTRAP here.
				 */
				if (sig == SIGSTOP ||
				    sig == SIGTSTP ||
				    sig == SIGTTIN ||
				    sig == SIGTTOU
				) {
					stopped = true;
					goto handle_stopsig;
				}
			}
#endif
#ifdef WANT_SECCOMP
			else if (event == PINK_EVENT_SECCOMP) {
				if ((r = event_seccomp(current)) < 0)
					continue; /* process dead */
			}
#endif
			goto restart_tracee_with_sig_0;
		}

		/* Is this post-attach SIGSTOP?
		 * Interestingly, the process may stop
		 * with STOPSIG equal to some other signal
		 * than SIGSTOP if we happend to attach
		 * just before the process takes a signal.
		 */
		if (sig == SIGSTOP && current->flags & SYD_IGNORE_ONE_SIGSTOP) {
			log_trace("ignored SIGSTOP");
			current->flags &= ~SYD_IGNORE_ONE_SIGSTOP;
			goto restart_tracee_with_sig_0;
		}

		if (sig != syscall_trap_sig) {
			siginfo_t si;

			/* Nonzero (true) if tracee is stopped by signal
			 * (as opposed to "tracee received signal").
			 * TODO: shouldn't we check for errno == EINVAL too?
			 * We can get ESRCH instead, you know...
			 */
			stopped = (pink_trace_get_siginfo(pid, &si) < 0);
#if PINK_HAVE_SEIZE
handle_stopsig:
#endif
			if (!stopped)
				/* It's signal-delivery-stop. Inject the signal */
				goto restart_tracee;

			/* It's group-stop */
#if PINK_HAVE_SEIZE
			if (syd_use_seize) {
				/*
				 * This ends ptrace-stop, but does *not* end group-stop.
				 * This makes stopping signals work properly on straced process
				 * (that is, process really stops. It used to continue to run).
				 */
				if ((r = pink_trace_listen(pid) < 0))
					ptrace_error(current, "PTRACE_LISTEN", -r);
				continue;
			}
			/* We don't have PTRACE_LISTEN support... */
#endif
			goto restart_tracee;
		}

		/* We handled quick cases, we are permitted to interrupt now. */
		if (interrupted) {
			sig = interrupted;
			return handle_interrupt(sig);
		}

		/* This should be syscall entry or exit.
		 * (Or it still can be that pesky post-execve SIGTRAP!)
		 * Handle it.
		 */
		r = event_syscall(current);
		if (r != 0) {
			/* ptrace() failed in event_syscall().
			 * Likely a result of process disappearing mid-flight.
			 * Observed case: exit_group() or SIGKILL terminating
			 * all processes in thread group.
			 * We assume that ptrace error was caused by process death.
			 * The process is ignored and will report its death to us
			 * normally, via WIFEXITED or WIFSIGNALED exit status.
			 */
			continue;
		}
restart_tracee_with_sig_0:
		sig = 0;
restart_tracee:
		ptrace_step(current, sig);
	}
cleanup:
	r = sydbox->exit_code;
	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			r = sydbox->config.violation_exit_code;
		else if (sydbox->config.violation_exit_code == 0)
			r = 128 + sydbox->exit_code;
	}

	log_context(NULL);
	log_info("return value %d (%s access violations)",
		 r, sydbox->violation ? "due to" : "no");
	return r;
}

int main(int argc, char **argv)
{
	int opt, r;
	const char *env;

	int ptrace_options;
	enum syd_step ptrace_default_step;

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"profile",	required_argument,	NULL,	0},
		{NULL,		0,		NULL,	0},
	};

	/* early initialisations */
	init_early();

	/* Make sure SIGCHLD has the default action so that waitpid
	   definitely works without losing track of children.  The user
	   should not have given us a bogus state to inherit, but he might
	   have.  Arguably we should detect SIG_IGN here and pass it on
	   to children, but probably noone really needs that.  */
	signal(SIGCHLD, SIG_DFL);

	while ((opt = getopt_long(argc, argv, "hvc:m:E:", long_options, &options_index)) != EOF) {
		switch (opt) {
		case 0:
			if (streq(long_options[options_index].name, "profile")) {
				/* special case for backwards compatibility */
				profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 1));
				profile_name[0] = SYDBOX_PROFILE_CHAR;
				strcat(profile_name, optarg);
				config_parse_spec(profile_name);
				free(profile_name);
				break;
			}
			usage(stderr, 1);
		case 'h':
			usage(stdout, 0);
		case 'v':
			about();
			return 0;
		case 'c':
			config_parse_spec(optarg);
			break;
		case 'm':
			r = magic_cast_string(NULL, optarg, 0);
			if (MAGIC_ERROR(r))
				die("invalid magic: `%s': %s",
				    optarg, magic_strerror(r));
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (optind == argc)
		usage(stderr, 1);

	if ((env = getenv(SYDBOX_CONFIG_ENV)))
		config_parse_spec(env);

	config_done();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC;
	ptrace_default_step = SYD_STEP_SYSCALL;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK
				| PINK_TRACE_OPTION_VFORK
				| PINK_TRACE_OPTION_CLONE);
	if (sydbox->config.use_seccomp) {
#ifdef WANT_SECCOMP
		ptrace_options |= PINK_TRACE_OPTION_SECCOMP;
		ptrace_default_step = SYD_STEP_RESUME;
#else
		log_info("seccomp not supported, disabling");
		sydbox->config.use_seccomp = false;
#endif
	}
	if (sydbox->config.use_seize) {
#if PINK_HAVE_SEIZE
		post_attach_sigstop = 0; /* this sets syd_use_seize to 1 */
#else
		log_info("seize not supported, disabling");
		sydbox->config.use_seize = false;
#endif
	}

	sydbox->trace_options = ptrace_options;
	sydbox->trace_step = ptrace_default_step;

	/*
	 * Initial program_invocation_name to be used for current->comm.
	 * Saves one proc_comm() call.
	 */
	sydbox->program_invocation_name = xstrdup(argv[optind]);

	/* Set useful environment variables for children */
	setenv("SYDBOX", SEE_EMILY_PLAY, 1);
	setenv("SYDBOX_VERSION", VERSION, 1);

	/* Poison! */
	if (streq(argv[optind], "/bin/sh"))
		fprintf(stderr, "[01;35m" PINK_FLOYD "[00;00m");

	/* STARTUP_CHILD must be called before the signal handlers get
	   installed below as they are inherited into the spawned process.
	   Also we do not need to be protected by them as during interruption
	   in the STARTUP_CHILD mode we kill the spawned process anyway.  */
	startup_child(&argv[optind]);
	init_signals();
	r = trace();
	cleanup();
	return r;
}
