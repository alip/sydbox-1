/*
 * sydbox/sydbox.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Released under the terms of the 3-clause BSD license
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
#if SYDBOX_HAVE_SECCOMP
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
#if SYDBOX_HAVE_SECCOMP
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

	newproc->pid = pid;
	if ((r = pink_regset_alloc(&newproc->regset)) < 0) {
		errno = -r;
		return NULL;
	}
	newproc->ppid = 0;
	newproc->trace_step = SYD_STEP_NOT_SET;
	newproc->flags = SYD_STARTUP | flags;

	SYD_PROCESS_ADD(newproc);
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
	if (p->flags & SYD_IGNORE)
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
	if (p->flags & SYD_IGNORE)
		return;
	pid = p->pid;

	/*
	 * We need the regset to determine system call entry of
	 * fork/vfork/clone! That's why we free it in remove_proc().
	 */
	if (p->abspath) {
		free(p->abspath);
		p->abspath = NULL;
	}
	if (p->cwd) {
		free(p->cwd);
		p->cwd = NULL;
	}
	if (p->comm) {
		free(p->comm);
		p->comm = NULL;
	}
	if (p->savebind) {
		free_sockinfo(p->savebind);
		p->savebind = NULL;
	}
	if (p->sockmap) {
		sockmap_destroy(&p->sockmap);
		p->sockmap = NULL;
	}

	/* Free the sandbox */
	free_sandbox(&p->config);

	p->flags |= SYD_IGNORE;
	log_context(NULL);
	log_trace("process %u ignored", pid);
}

void remove_proc(syd_proc_t *p)
{
	pid_t pid;

	if (!p)
		return;
	pid = p->pid;

	SYD_PROCESS_REMOVE(p);
	ignore_proc(p);
	if (p->regset)
		pink_regset_free(p->regset);
	free(p);

	log_context(NULL);
	log_trace("process %u removed", pid);
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

	pid_t pid = current->pid;
	short abi = current->abi;
	pid_t ppid = current->ppid;
	struct acl_node *node;
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
	if (current->flags & SYD_STARTUP) {
		fprintf(stderr, "STARTUP");
		r = 1;
	}
	if (current->flags & SYD_IGNORE_ONE_SIGSTOP) {
		fprintf(stderr, "%sIGNORE_ONE_SIGSTOP", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IGNORE) {
		fprintf(stderr, "%sIGNORE", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_READY) {
		fprintf(stderr, "%sREADY", (r == 1) ? "|" : "");
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
	ACLQ_FOREACH(node, &current->config.acl_exec)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &current->config.acl_read)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &current->config.acl_write)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	ACLQ_FOREACH(node, &current->config.acl_network_bind) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	ACLQ_FOREACH(node, &current->config.acl_network_connect) {
		match = node->match;
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
	syd_proc_t *node, *tmp;

	if (!sydbox)
		return;

	complete_dump= !!(signo == SIGUSR2);

	fprintf(stderr, "\nsydbox: Received SIGUSR%s, dumping %sprocess tree\n",
		complete_dump ? "2" : "1",
		complete_dump ? "complete " : "");
	count = 0;
	SYD_PROCESS_ITER(node, tmp) {
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
	sydbox->proctab = NULL;
	sydbox->violation = false;
	sydbox->pidwait = 0;
	sydbox->wait_execve = false;
	sydbox->exit_code = EXIT_SUCCESS;
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
	struct acl_node *node;

	assert(sydbox);

	/* Free the global configuration */
	free_sandbox(&sydbox->config.child);

	ACLQ_FREE(node, &sydbox->config.exec_kill_if_match, free);
	ACLQ_FREE(node, &sydbox->config.exec_resume_if_match, free);

	ACLQ_FREE(node, &sydbox->config.filter_exec, free);
	ACLQ_FREE(node, &sydbox->config.filter_read, free);
	ACLQ_FREE(node, &sydbox->config.filter_write, free);
	ACLQ_FREE(node, &sydbox->config.filter_network, free_sockmatch);

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
#if SYDBOX_HAVE_SECCOMP
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
		    (r = pink_trace_interrupt(pid)) < 0) {
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
		err_fatal(err_no, "ptrace(%s, %u) failed", req, current->pid);
		return panic(current);
	}
	ignore_proc(current);
	return -ESRCH;
}

static int ptrace_step(syd_proc_t *current, int sig)
{
	int r;
	enum syd_step step;
	const char *msg;

	step = current->trace_step == SYD_STEP_NOT_SET
	       ? sydbox->trace_step
	       : current->trace_step;

	switch (step) {
	case SYD_STEP_SYSCALL:
		r = pink_trace_syscall(current->pid, sig);
		msg = "PTRACE_SYSCALL";
		break;
	case SYD_STEP_RESUME:
		r = pink_trace_resume(current->pid, sig);
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
	struct acl_node *node, *newnode;
	sandbox_t *inherit;

	if (!parent) {
		comm = xstrdup(sydbox->program_invocation_name);
		cwd = xgetcwd();
		inherit = &sydbox->config.child;
	} else {
		if (parent->flags & SYD_IGNORE) {
			/* parent is ignored, ignore the child too */
			comm = cwd = NULL;
			current->comm = current->cwd = NULL;
			current->flags |= SYD_IGNORE;
			return;
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
	current->sockmap = NULL;

	/* Copy the lists  */
	ACLQ_DUP(node, &inherit->acl_exec, &current->config.acl_exec, newnode, xstrdup);
	ACLQ_DUP(node, &inherit->acl_read, &current->config.acl_read, newnode, xstrdup);
	ACLQ_DUP(node, &inherit->acl_write, &current->config.acl_write, newnode, xstrdup);
	ACLQ_DUP(node, &inherit->acl_network_bind, &current->config.acl_network_bind, newnode, sockmatch_xdup);
	ACLQ_DUP(node, &inherit->acl_network_connect, &current->config.acl_network_connect, newnode, sockmatch_xdup);

	if (sydbox->config.whitelist_per_process_directories) {
		char magic[sizeof("/proc/%u/***") + sizeof(int)*3 + /*paranoia:*/16];
		sprintf(magic, "/proc/%u/***", current->pid);
		magic_append_whitelist_read(magic, current);
		magic_append_whitelist_write(magic, current);
	}
}

static int init_sandbox(syd_proc_t *current)
{
	pid_t pid;
	syd_proc_t *parent;

	if (current->flags & SYD_READY)
		return 0;

	pid = current->pid;

	if (sydchild(current)) {
		inherit_sandbox(current, NULL);
		goto out;
	} else if (hasparent(current)) {
		parent = lookup_proc(current->ppid);
		if (!parent)
			die("Unknown parent pid: %u", current->ppid);
		inherit_sandbox(current, parent);
		goto out;
	}

	log_warning("parent is gone before we could inherit sandbox");
	log_warning("inheriting global (unmodified) sandbox");
	inherit_sandbox(current, NULL);
out:
	current->flags |= SYD_READY;
	log_trace("process %u is ready for access control", pid);
	return 0;
}

static int event_startup(syd_proc_t *current)
{
	int r;

	if ((r = syd_trace_setup(current)) < 0)
		return ptrace_error(current, "PTRACE_SETOPTIONS", -r);
	if ((r = init_sandbox(current)) < 0)
		return r; /* process dead */
	current->flags &= ~SYD_STARTUP;
	return 0;
}

static int event_fork(syd_proc_t *current)
{
	int r;
	pid_t pid, cpid;
	syd_proc_t *child;

	if ((r = syd_trace_geteventmsg(current, (unsigned long *)&cpid)) < 0)
		return r; /* process dead */

	pid = current->pid;
	child = lookup_proc(cpid);
	if (child) {
		log_warning("[%s] child %u of %u is in process list", __func__,
			    cpid, pid);
		return 0;
	}

	child = add_proc_or_kill(cpid, post_attach_sigstop);
	child->ppid = pid;

	log_context(child);
	inherit_sandbox(child, current);
	child->flags |= SYD_READY;
	log_context(current);

	return 0;
}

static int event_exec(syd_proc_t *current)
{
	int e, r;
	char *comm;
	const char *match;

	if (sydbox->wait_execve) {
		log_info("[wait_execve]: execve() ptrace trap");
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp) {
			log_info("[wait_execve]: sandboxing started");
			sydbox->wait_execve = false;
		}
#endif
		return 0;
	}

	if (current->flags & SYD_IGNORE)
		return 0;

	if (current->config.magic_lock == LOCK_PENDING) {
		log_magic("locked magic commands");
		current->config.magic_lock = LOCK_SET;
	}

	if (!current->abspath) /* nothing left to do */
		return 0;

	/* kill_if_match and resume_if_match */
	r = 0;
	if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_kill_if_match,
			   current->abspath, &match)) {
		log_warning("kill_if_match pattern=`%s' matches execve path=`%s'",
			    match, current->abspath);
		log_warning("killing process");
		syd_trace_kill(current, SIGKILL);
		ignore_proc(current);
		return -ESRCH;
	} else if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_resume_if_match,
				  current->abspath, &match)) {
		log_warning("resume_if_match pattern=`%s' matches execve path=`%s'",
			    match, current->abspath);
#if SYDBOX_HAVE_SECCOMP
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

static int event_syscall(syd_proc_t *current)
{
	int r = 0;

	if (sydbox->wait_execve) {
#if SYDBOX_HAVE_SECCOMP
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

	if (current->flags & SYD_IGNORE)
		return 0;

	if (entering(current)) {
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp &&
		    (current->flags & SYD_STOP_AT_SYSEXIT)) {
			log_trace("seccomp: skipping sysenter");
			current->flags |= SYD_IN_SYSCALL;
			return 0;
		}
#endif
		if ((r = syd_regset_fill(current)) < 0)
			return r; /* process dead */
		r = sysenter(current);
#if SYDBOX_HAVE_SECCOMP
		if (sydbox->config.use_seccomp &&
		    !(current->flags & SYD_STOP_AT_SYSEXIT)) {
			log_trace("seccomp: skipping sysexit, resuming");
			current->trace_step = SYD_STEP_RESUME;
			return r;
		}
#endif
		current->flags |= SYD_IN_SYSCALL;
	} else {
		if ((r = syd_regset_fill(current)) < 0)
			return r; /* process dead */
		r = sysexit(current);
		current->flags &= ~SYD_IN_SYSCALL;
	}
	return r;
}

#if SYDBOX_HAVE_SECCOMP
static int event_seccomp(syd_proc_t *current)
{
	int r;

	if (sydbox->wait_execve) {
		log_info("[wait_execve]: execve() seccomp trap");
		return 0;
	}

	/*
	 * Note: We can't return here in case SYD_IGNORE is set, because
	 * otherwise sys_fork() callback can not set sydbox->pidwait which in
	 * turn means we will face the well-known race condition between child
	 * stop and parent fork! This only makes sense for seccomp because
	 * processes are just removed (not ignored) otherwise.
	 */

	if ((r = syd_regset_fill(current)) < 0)
		return r; /* process dead */
	r = sysenter(current);
	if (current->flags & SYD_STOP_AT_SYSEXIT) {
		/* step using PTRACE_SYSCALL until we hit sysexit. */
		current->flags &= ~SYD_IN_SYSCALL;
		current->trace_step = SYD_STEP_SYSCALL;
	}
	return r;
}
#endif

static int event_exit(syd_proc_t *current)
{
	int code = EXIT_FAILURE;
	int r, status;

	if ((r = syd_trace_geteventmsg(current, (unsigned long *)&status)) < 0)
		return r; /* process dead */

	if (WIFEXITED(status)) {
		code = WEXITSTATUS(status);
		log_trace("exiting with code:%d (status:0x%04x)", code, status);
	} else {
		code = 128 + WTERMSIG(status);
		log_trace("terminating with signal:%d (status:0x%04x)",
			  WTERMSIG(status), status);
	}

	if (sydchild(current)) {
		sydbox->exit_code = code;
		if (!sydbox->config.exit_wait_all) {
			log_trace("aborting loop (wait_all not set)");
			cont_all();
			exit(sydbox->exit_code);
		}
	}
	return 0;
}

static int trace(void)
{
	int pid, wait_pid, wait_errno;
	bool stopped;
	int r;
	int status, sig;
	unsigned event;
	syd_proc_t *current;
	int syscall_trap_sig;

	syscall_trap_sig = sydbox->trace_options & PINK_TRACE_OPTION_SYSGOOD
			   ? SIGTRAP | 0x80
			   : SIGTRAP;
	/*
	 * Used to be while(SYD_PROCESS_COUNT() > 0), but in this testcase:
	 * int main() { _exit(!!fork()); }
	 * under sydbox, parent sometimes (rarely) manages
	 * to exit before we see the first stop of the child,
	 * and we are losing track of it.
	 *
	 * Waiting for ECHILD works better.
	 */
	while (1) {
		log_context(NULL);

		if (interrupted) {
			sig = interrupted;
			return handle_interrupt(sig);
		}

		wait_pid = sydbox->pidwait > 0 ? sydbox->pidwait : -1;
		if (interactive)
			sigprocmask(SIG_SETMASK, &empty_set, NULL);
		pid = waitpid(wait_pid, &status, __WALL);
		wait_errno = errno;
		if (interactive)
			sigprocmask(SIG_SETMASK, &blocked_set, NULL);

		if (pid < 0) {
			switch (wait_errno) {
			case EINTR:
				continue;
			case ECHILD:
				if (SYD_PROCESS_COUNT() == 0)
					goto cleanup;
				/* If process count > 0, ECHILD is not expected,
				 * treat it as any other error here.
				 * fall through...
				 */
			default:
				err_fatal(wait_errno, "wait failed");
				goto cleanup;
			}
		} else {
			sydbox->pidwait = 0;
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
			log_trace("[wait(%d, 0x%04x) = %u] %s%s", wait_pid, status,
				  pid, buf, evbuf);
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
			current->pid = pid;
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
			remove_proc(current);
			continue;
		}

		if (!WIFSTOPPED(status)) {
			log_fatal("PANIC: not stopped (status:0x%04x)", status);
			panic(current);
			continue;
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
#if SYDBOX_HAVE_SECCOMP
			else if (event == PINK_EVENT_SECCOMP) {
				if ((r = event_seccomp(current)) < 0)
					continue; /* process dead */
			}
#endif
			else if (event == PINK_EVENT_EXIT) {
				if ((r = event_exit(current)) < 0)
					continue; /* process dead */
			}
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

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD |
			 PINK_TRACE_OPTION_EXEC |
			 PINK_TRACE_OPTION_EXIT;
	ptrace_default_step = SYD_STEP_SYSCALL;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK |
				   PINK_TRACE_OPTION_VFORK |
				   PINK_TRACE_OPTION_CLONE);
#if PINK_HAVE_OPTION_EXITKILL
	if (sydbox->config.exit_kill)
		ptrace_options |= PINK_TRACE_OPTION_EXITKILL;
#endif
	if (sydbox->config.use_seccomp) {
#if SYDBOX_HAVE_SECCOMP
		if (os_release >= KERNEL_VERSION(3,5,0)) {
			ptrace_options |= PINK_TRACE_OPTION_SECCOMP;
			ptrace_default_step = SYD_STEP_RESUME;
		} else {
			log_warning("Linux-3.5.0 required for seccomp support, disabling");
			sydbox->config.use_seccomp = false;
		}
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
	setenv("SYDBOX_API_VERSION", STRINGIFY(SYDBOX_API_VERSION), 1);
	setenv("SYDBOX_ACTIVE", THE_PIPER, 1);

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
