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

static void sig_usr(int signo);

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

static void new_shared_memory_clone_thread(struct syd_process *p)
{
	int r;

	p->shm.clone_thread = xmalloc(sizeof(struct syd_process_shared_clone_thread));
	p->shm.clone_thread->refcnt = 1;
	p->shm.clone_thread->comm = NULL;
	if ((r = new_sandbox(&p->shm.clone_thread->box)) < 0) {
		free(p->shm.clone_thread);
		errno = -r;
		die_errno("new_sandbox");
	}
}

static void new_shared_memory_clone_fs(struct syd_process *p)
{
	p->shm.clone_fs = xmalloc(sizeof(struct syd_process_shared_clone_fs));
	p->shm.clone_fs->refcnt = 1;
	p->shm.clone_fs->cwd = NULL;
}

static void new_shared_memory_clone_files(struct syd_process *p)
{
	p->shm.clone_files = xmalloc(sizeof(struct syd_process_shared_clone_files));
	p->shm.clone_files->refcnt = 1;
	p->shm.clone_files->savebind = NULL;
	p->shm.clone_files->sockmap = NULL;
}

static void new_shared_memory(struct syd_process *p)
{
	new_shared_memory_clone_thread(p);
	new_shared_memory_clone_fs(p);
	new_shared_memory_clone_files(p);
}

static syd_process_t *new_thread(pid_t pid, short flags)
{
	int r;
	syd_process_t *thread;

	thread = calloc(1, sizeof(syd_process_t));
	if (!thread)
		return NULL;

	thread->pid = pid;

	if ((r = pink_regset_alloc(&thread->regset)) < 0) {
		free(thread);
		errno = -r;
		return NULL;
	}

	thread->abi = PINK_ABI_DEFAULT;
	thread->flags = SYD_STARTUP | flags;
	thread->trace_step = SYD_STEP_NOT_SET;

	return thread;
}

static syd_process_t *new_process(pid_t pid, short flags)
{
	syd_process_t *process;

	process = new_thread(pid, flags);
	if (!process)
		return NULL;
	new_shared_memory(process);

	return process;
}

static syd_process_t *new_thread_or_kill(pid_t pid, short flags)
{
	syd_process_t *thread;

	thread = new_thread(pid, flags);
	if (!thread) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return thread;
}

static syd_process_t *new_process_or_kill(pid_t pid, short flags)
{
	syd_process_t *process;

	process = new_process(pid, flags);
	if (!process) {
		kill_save_errno(pid, SIGKILL);
		die_errno("malloc() failed, killed %u", pid);
	}

	return process;
}

void reset_process(syd_process_t *p)
{
	if (!p)
		return;

	p->sysnum = 0;
	p->sysname = NULL;
	memset(p->args, 0, sizeof(p->args));
	p->subcall = 0;
	p->retval = 0;
	p->flags &= ~SYD_DENY_SYSCALL;
	p->flags &= ~SYD_STOP_AT_SYSEXIT;

	if (P_SAVEBIND(p)) {
		free_sockinfo(P_SAVEBIND(p));
		P_SAVEBIND(p) = NULL;
	}
}

void free_process(syd_process_t *p)
{
	static pid_t pid;

	if (!p)
		return;
	pid = p->pid;

	if (p->abspath)
		free(p->abspath);
	if (p->regset)
		pink_regset_free(p->regset);

	process_remove(p);

	/* Release shared memory */
	P_CLONE_THREAD_RELEASE(p);
	P_CLONE_FS_RELEASE(p);
	P_CLONE_FILES_RELEASE(p);

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

static bool dump_one_process(syd_process_t *current, bool verbose)
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
	if (sydchild(current))
		fprintf(stderr, "\t%sParent ID: SYDBOX%s\n", CN, CE);
	else if (current->ppid > 0)
		fprintf(stderr, "\t%sParent ID: %u%s\n", CN, ppid > 0 ? ppid : 0, CE);
	else
		fprintf(stderr, "\t%sParent ID: ? (Orphan)%s\n", CN, CE);
	fprintf(stderr, "\t%sComm: `%s'%s\n", CN, P_COMM(current), CE);
	fprintf(stderr, "\t%sCwd: `%s'%s\n", CN, P_CWD(current), CE);
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
	if (current->flags & SYD_READY) {
		fprintf(stderr, "%sREADY", (r == 1) ? "|" : "");
		r = 1;
	}
	if (current->flags & SYD_IN_LABOUR) {
		fprintf(stderr, "%sIN_LABOUR", (r == 1) ? "|" : "");
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
	if (current->clone_flags & (CLONE_THREAD|CLONE_FS|CLONE_FILES)) {
		fprintf(stderr, "\t%sClone flags: ", CN);
		r = 0;
		if (current->clone_flags & CLONE_THREAD) {
			fprintf(stderr, "%sCLONE_THREAD{ref=%u}", (r == 1) ? "|" : "",
				current->shm.clone_thread ? current->shm.clone_thread->refcnt : 0);

			r = 1;
		}
		if (current->clone_flags & CLONE_FS) {
			fprintf(stderr, "%sCLONE_FS{ref=%u}", (r == 1) ? "|" : "",
				current->shm.clone_fs ? current->shm.clone_fs->refcnt : 0);
			r = 1;
		}
		if (current->clone_flags & CLONE_FILES) {
			fprintf(stderr, "%sCLONE_FILES{ref=%u}", (r == 1) ? "|" : "",
				current->shm.clone_files ? current->shm.clone_files->refcnt : 0);
			r = 1;
		}
		if (current->clone_flags & CLONE_VFORK) {
			fprintf(stderr, "%sCLONE_VFORK", (r == 1) ? "|" : "");
			r = 1;
		}
		fprintf(stderr, "%s\n", CN);
	} else {
		fprintf(stderr, "\t%sClone flags: 0%s\n", CN, CN);
	}

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
		sandbox_mode_to_string(P_BOX(current)->sandbox_exec),
		sandbox_mode_to_string(P_BOX(current)->sandbox_read),
		sandbox_mode_to_string(P_BOX(current)->sandbox_write),
		sandbox_mode_to_string(P_BOX(current)->sandbox_network),
		CE);
	fprintf(stderr, "\t%sMagic Lock: %s%s\n", CN, lock_state_to_string(P_BOX(current)->magic_lock), CE);
	fprintf(stderr, "\t%sExec Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_exec)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_read)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_write)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->match, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_bind) {
		match = node->match;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, (void *)match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	ACLQ_FOREACH(node, &P_BOX(current)->acl_network_connect) {
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
	syd_process_t *node, *tmp;

	if (!sydbox)
		return;

	complete_dump= !!(signo == SIGUSR2);

	fprintf(stderr, "\nsydbox: Received SIGUSR%s, dumping %sprocess tree\n",
		complete_dump ? "2" : "1",
		complete_dump ? "complete " : "");
	count = 0;
	process_iter(node, tmp) {
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

	reset_sandbox(&sydbox->config.box_static);

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
	syd_process_t *child;

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
	child = new_process_or_kill(pid, SYD_SYDBOX_CHILD | post_attach_sigstop);
	process_add(child);

	sydbox->wait_execve = true;
}

static int handle_interrupt(int fatal_sig)
{
	if (!fatal_sig)
		fatal_sig = SIGTERM;

	abort_all(fatal_sig);
	return 128 + fatal_sig;
}

static int ptrace_error(syd_process_t *current, const char *req, int err_no)
{
	if (err_no != ESRCH) {
		err_fatal(err_no, "ptrace(%s, %u) failed", req, current->pid);
		return panic(current);
	}
	free_process(current);
	return -ESRCH;
}

static int ptrace_step(syd_process_t *current, int sig)
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

static void inherit_shareable_data(syd_process_t *current, syd_process_t *parent)
{
	bool share_thread, share_fs, share_files;

	share_thread = share_fs = share_files = false;
	if (parent && parent->new_clone_flags) {
		if (parent->new_clone_flags & CLONE_THREAD)
			share_thread = true;
		if (parent->new_clone_flags & CLONE_FS)
			share_fs = true;
		if (parent->new_clone_flags & CLONE_FILES)
			share_files = true;
		}

	if (sydchild(current)) {
		P_COMM(current) = xstrdup(sydbox->program_invocation_name);
		P_CWD(current) = xgetcwd();
		copy_sandbox(P_BOX(current), box_current(NULL));
	} else if (!hasparent(current)) {
		log_warning("inheriting global (unmodified) sandbox");
		P_CWD(current) = xgetcwd();
		copy_sandbox(P_BOX(current), box_current(NULL));
	} else {
		/*
		 * Link together for memory sharing.
		 * Note: thread in this context is any process which shares memory.
		 * (May not always be a real thread: (e.g. vfork)
		 */
		current->clone_flags = parent->new_clone_flags;

		if (share_thread) {
			current->shm.clone_thread = parent->shm.clone_thread;
			P_CLONE_THREAD_RETAIN(current);
		} else {
			new_shared_memory_clone_thread(current);
			P_COMM(current) = xstrdup(P_COMM(parent));
			copy_sandbox(P_BOX(current), box_current(parent));
		}

		if (share_fs) {
			current->shm.clone_fs = parent->shm.clone_fs;
			P_CLONE_FS_RETAIN(current);
		} else {
			new_shared_memory_clone_fs(current);
			P_CWD(current) = xstrdup(P_CWD(parent));
		}

		if (share_files) {
			current->shm.clone_files = parent->shm.clone_files;
			P_CLONE_FILES_RETAIN(current);
		} else {
			new_shared_memory_clone_files(current);
		}
	}
}

static void inherit_process_data(syd_process_t *current, syd_process_t *parent)
{
	inherit_shareable_data(current, parent);

	if (sydbox->config.whitelist_per_process_directories &&
	    (!parent || current->pid != parent->pid)) {
		char magic[sizeof("/proc/%u/***") + sizeof(int)*3 + /*paranoia:*/16];
		sprintf(magic, "/proc/%u/***", current->pid);
		magic_append_whitelist_read(magic, current);
		magic_append_whitelist_write(magic, current);
	}
}

static void init_process_data(syd_process_t *current)
{
	pid_t pid;
	syd_process_t *parent;

	if (current->flags & SYD_READY)
		return;

	pid = current->pid;

	if (sydchild(current)) {
		inherit_process_data(current, NULL);
		goto out;
	}

	parent = NULL;
	if (hasparent(current)) {
		parent = lookup_process(current->ppid);
		if (parent) {
			inherit_process_data(current, parent);
			goto out;
		}
		log_warning("invalid parent process %d", current->ppid);
	} else if (orphan(current)) {
		log_warning("process %d is an orphan", current->pid);
	} else {
		log_warning("process %d has no parent", current->pid);
	}

	inherit_process_data(current, NULL);
out:
	current->flags |= SYD_READY;
	log_trace("process %u is ready for access control", pid);
}

static int event_startup(syd_process_t *current)
{
	int r;

	if ((r = syd_trace_setup(current)) < 0)
		return ptrace_error(current, "PTRACE_SETOPTIONS", -r);
	init_process_data(current);
	current->flags &= ~SYD_STARTUP;
	return 0;
}

static int event_clone(syd_process_t *current, pid_t cpid_early)
{
	int r = 0;
	pid_t pid, cpid;
	syd_process_t *thread = NULL;
	bool waiting_for_me = false;

	assert(current);
	if (sydbox->pidwait == current->pid) {
		waiting_for_me = true;
		sydbox->pidwait = -1;
	}

	if (!(current->flags & SYD_IN_LABOUR)) {
		/*
		 * Child was born early and event_clone was simulated.
		 * Nothing left to do.
		 */
		goto out;
	}
	current->flags &= ~SYD_IN_LABOUR;

	/*
	 * The second argument is > -1 if the child's initial SIGSTOP
	 * came before EVENT_CLONE
	 */
	if (cpid_early != -1)
		cpid = cpid_early;
	else if ((r = syd_trace_geteventmsg(current, (unsigned long *)&cpid)) < 0)
		goto out; /* process dead */

	pid = current->pid;
	thread = lookup_process(cpid);
	if (!thread) {
		thread = new_thread_or_kill(cpid, post_attach_sigstop);
	} else if (hasparent(thread)) {
		if (thread->ppid == current->pid)
			log_warning("[%s] error: child %u of current process %d is already in process list",
				    __func__, cpid, pid);
		else
			log_warning("[%s] WTF! child %u of %u is already in process list",
				    __func__, cpid, pid);
		goto out;
	}

	process_add(thread);
	thread->ppid = pid;
	inherit_process_data(thread, current); /* expects ->ppid to be valid. */
	thread->flags |= SYD_READY;
	current->new_clone_flags = 0;

out:
	if (waiting_for_me)
		log_trace("reset wait_pid %d to -1 after clone %d", pid, cpid);
	return r;
}

static int event_exec(syd_process_t *current)
{
	int e, r;
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

	assert(current);

	if (P_BOX(current)->magic_lock == LOCK_PENDING) {
		log_magic("locked magic commands");
		P_BOX(current)->magic_lock = LOCK_SET;
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
		return -ESRCH;
	} else if (acl_match_path(ACL_ACTION_NONE, &sydbox->config.exec_resume_if_match,
				  current->abspath, &match)) {
		log_warning("resume_if_match pattern=`%s' matches execve path=`%s'",
			    match, current->abspath);
		log_warning("detaching from process");
		syd_trace_detach(current, 0);
		return -ESRCH;
	} else {
		log_match("execve path=`%s' does not match if_match patterns",
			  current->abspath);
	}

	char *new_comm, *new_cwd;

	/* Update process memory */
	if ((e = basename_alloc(current->abspath, &new_comm))) {
		err_warning(-e, "updating process name failed");
		new_comm = xstrdup("???");
	} else if (strcmp(new_comm, P_COMM(current))) {
		log_info("updating process name to `%s' due to execve()", new_comm);
	}

	if (P_CLONE_THREAD_REFCNT(current) > 1) {
		struct syd_process_shared_clone_thread *old = current->shm.clone_thread;
		struct syd_process_shared_clone_thread *new;

		/* XXX: This is way too ugly. */
		new_shared_memory_clone_thread(current);
		new = current->shm.clone_thread;
		P_COMM(current) = new_comm;
		copy_sandbox(P_BOX(current), old->box);
		current->shm.clone_thread = old;
		P_CLONE_THREAD_RELEASE(current);
		current->shm.clone_thread = new;
	} else {
		free(P_COMM(current));
		P_COMM(current) = new_comm;
	}

	if (P_CLONE_FS_REFCNT(current) > 1) {
		new_cwd = xstrdup(P_CWD(current));
		P_CLONE_FS_RELEASE(current);
		new_shared_memory_clone_fs(current);
		P_CWD(current) = new_cwd;
	}

	if (P_CLONE_FILES_REFCNT(current) > 1) {
		P_CLONE_FILES_RELEASE(current);
		new_shared_memory_clone_files(current);
	} else {
		if (P_SAVEBIND(current)) {
			free_sockinfo(P_SAVEBIND(current));
			P_SAVEBIND(current) = NULL;
		}
		if (P_SOCKMAP(current)) {
			sockmap_destroy(&P_SOCKMAP(current));
			P_SOCKMAP(current) = NULL;
		}
	}

	free(current->abspath);
	current->abspath = NULL;

	return r;
}

static int event_syscall(syd_process_t *current)
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
static int event_seccomp(syd_process_t *current)
{
	int r;

	if (sydbox->wait_execve) {
		log_info("[wait_execve]: execve() seccomp trap");
		return 0;
	}

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

static int event_exit(syd_process_t *current)
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
	int pid, wait_pid, wait_errno, wait_options;
	bool stopped;
	int r;
	int status, sig;
	unsigned event;
	syd_process_t *current, *parent;
	int syscall_trap_sig;

	syscall_trap_sig = sydbox->trace_options & PINK_TRACE_OPTION_SYSGOOD
			   ? SIGTRAP | 0x80
			   : SIGTRAP;
	/*
	 * Used to be while(process_count() > 0), but in this testcase:
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

		if (sydbox->pidwait > 0) {
			wait_pid = sydbox->pidwait;
		} else {
			wait_pid = -1;
		}
		wait_options = __WALL;

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
				if (sydbox->pidwait > 0) {
					log_warning("wait(%d, %d) failed (errno:%d ECHILD)",
						    sydbox->pidwait, wait_options, ECHILD);
					log_warning("retrying to wait with -1");
					/* TODO: unset SYD_IN_LABOUR here! */
					sydbox->pidwait = -1;
					continue;
				}
				if (process_count() == 0)
					goto cleanup;
				/* If process count > 0, ECHILD is not expected,
				 * treat it as any other error here.
				 * fall through...
				 */
			default:
				err_fatal(wait_errno, "wait(%d, %d) failed", sydbox->pidwait, wait_options);
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
			log_trace("[wait(%d, 0x%04x) = %u] %s%s", wait_pid, status,
				  pid, buf, evbuf);
		}

		current = lookup_process(pid);
		log_context(NULL);
		if (!current) {
			/*
			 * This can also happen due to a race condition for path:
			 * clone(2) -> New child born -> EVENT_CLONE
			 * (which is a race condition between child and parent)
			 *
			 * FIXME: This can happen if a clone call used CLONE_PTRACE itself.
			 */
			if (sydbox->pidwait != -1) {
				/* Simulate clone event */
				parent = lookup_process(sydbox->pidwait);
				if (!parent) {
					log_warning("parent %d gone before child birth", sydbox->pidwait);
					log_warning("child %d is an orphan", pid);
					current = new_thread_or_kill(pid, post_attach_sigstop);
					goto orphan;
				}
				event_clone(parent, pid);
				current = lookup_process(pid);
			} else {
				/* Add the (currently) orphan process to the
				 * process list. */
				current = new_thread_or_kill(pid, post_attach_sigstop);
			}
			log_context(current);
		} else if (!hasparent(current)) {
orphan:
			/*
			 * Process is an orphan.
			 * This is most probably because the parent is gone for
			 * good.
			 */
			current->ppid = SYD_PPID_ORPHAN;
			new_shared_memory(current);
			log_context(current);
			init_process_data(current);
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
			syd_process_t *execve_thread;
			long old_tid = 0;

			if ((r = pink_trace_geteventmsg(pid, (unsigned long *) &old_tid)) < 0
			    || old_tid <= 0)
				err_fatal(-r, "old pid not available after execve for pid:%u", pid);
			if (old_tid == pid)
				goto dont_switch_procs;
			execve_thread = lookup_process(old_tid);
			/* It should be !NULL, but someone feels paranoid */
			if (!execve_thread)
				err_fatal(-r, "old pid not available after execve for pid:%u", pid);
			log_trace("leader %lu superseded by execve in tid %u", old_tid, pid);
			/* Drop leader, switch to the thread, reusing leader's tid */
			execve_thread->pid = current->pid;
			execve_thread->ppid = current->ppid;
			execve_thread->clone_flags = current->clone_flags;
			current = execve_thread;
			log_context(current);
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
			free_process(current);
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
				if ((r = event_clone(current, -1)) < 0)
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
				strcpy(&profile_name[1], optarg);
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
	 * Initial program_invocation_name to be used for P_COMM(current).
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
