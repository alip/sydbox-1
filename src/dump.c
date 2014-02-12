/*
 * sydbox/dump.c
 *
 * Event dumper using JSON lines
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>

#include "dump.h"
#include "proc.h"

#define J(s)		"\""#s"\":"
#define J_BOOL(b)	(b) ? "true" : "false"

static FILE *fp;
static int nodump = -1;
static unsigned long flags;
static unsigned long long id;

static void dump_close(void)
{
	fclose(fp);
	fp = NULL;
}

static void dump_flush(void)
{
	fflush(fp);
}

static void dump_cycle(void)
{
	fputs("\n", fp);
	dump_flush();
}

static void dump_string(const char *s)
{
	unsigned i;

	for (i = 0; s[i] != '\0'; i++) {
		switch (s[i]) {
		case '"':
			fprintf(fp, "\\\"");
		case '\\':
			fprintf(fp, "\\\\");
		case '/':
			fprintf(fp, "\\/");
		case '\b':
			fprintf(fp, "\\b");
		case '\f':
			fprintf(fp, "\\f");
		case '\n':
			fprintf(fp, "\\n");
		case '\r':
			fprintf(fp, "\\r");
		case '\t':
			fprintf(fp, "\\t");
		/* case '\u' + 4 hexadecimal digits! */
		default:
			fprintf(fp, "%c", s[i]);
		}
	}
}

static void dump_quoted(const void *p)
{
	const char *s = p;

	fprintf(fp, "\"");
	dump_string(s);
	fprintf(fp, "\"");
}

static void dump_errno(int err_no)
{
	fprintf(fp, "{"
		J(errno)"%d,"
		J(errno_name)"\"%s\""
		"}",
		err_no, pink_name_errno(err_no, 0));
}

static void dump_wait_status(int status)
{
	fprintf(fp, "{"
		J(value)"%d,"
		J(WIFEXITED)"%s,"
		J(WIFSIGNALED)"%s,"
		J(WCOREDUMP)"%s,"
		J(WIFSTOPPED)"%s,"
		J(WIFCONTINUED)"%s,"
		J(WEXITSTATUS)"%u,"
		J(WTERMSIG)"%d,"
		J(WTERMSIG_name)"\"%s\","
		J(WSTOPSIG)"%d,"
		J(WSTOPSIG_name)"\"%s\","
		J(ptrace)"%d,"
		J(ptrace_name)"\"%s\"}",
		status,
		J_BOOL(WIFEXITED(status)),
		J_BOOL(WIFSIGNALED(status)),
		J_BOOL(WIFSIGNALED(status) && WCOREDUMP(status)),
		J_BOOL(WIFSTOPPED(status)),
		J_BOOL(WIFCONTINUED(status)),
		WIFEXITED(status) ? WEXITSTATUS(status) : 0,
		WIFSIGNALED(status) ? WTERMSIG(status) : 0,
		WIFSIGNALED(status) ? pink_name_signal(WTERMSIG(status), 0) : "null",
		WIFSTOPPED(status) ? WSTOPSIG(status) : 0,
		WIFSTOPPED(status) ? pink_name_signal(WSTOPSIG(status), 0) : "null",
		pink_event_decide(status),
		pink_name_event(pink_event_decide(status)));
}

static void dump_format(void)
{
	fprintf(fp, "{"
		J(id)"%llu,"
		J(shoebox)"%u}", id++, DUMP_FMT);
}

static void dump_proc_statinfo(const struct proc_statinfo *info)
{
	fprintf(fp, "{"
		J(pid)"%d,"J(ppid)"%d,"J(pgrp)"%d,"
		J(comm)"\"%s\","J(state)"\"%c\","
		J(session)"%d,"J(tty_nr)"%d,"J(tpgid)"%d,"
		J(nice)"%ld,"J(num_threads)"%ld"
		"}",
		info->pid, info->ppid, info->pgrp,
		info->comm, info->state,
		info->session, info->tty_nr, info->tpgid,
		info->nice, info->num_threads);
}

static void dump_aclq(const aclq_t *aclq, void (*dump_match_func)(const void *))
{
	int i = 0, j = 0;
	struct acl_node *node;

	assert(aclq != NULL);
	assert(dump_match_func != NULL);

	fprintf(fp, "[");
	ACLQ_FOREACH(node, aclq) i++;
	ACLQ_FOREACH(node, aclq) {
		dump_match_func(node->match);
		if (++j != i)
			fprintf(fp, ",");
	}
	fprintf(fp, "]");
}

static void dump_sandbox(const sandbox_t *box)
{
	assert(box != NULL);

	fprintf(fp, "{"
		J(exec)"%s,"
		J(read)"%s,"
		J(write)"%s,"
		J(network)"%s,"
		J(magic_lock)"%u,"
		J(magic_lock_name)"\"%s\"",
		J_BOOL(box->sandbox_exec),
		J_BOOL(box->sandbox_read),
		J_BOOL(box->sandbox_write),
		J_BOOL(box->sandbox_network),
		box->magic_lock,
		lock_state_to_string(box->magic_lock));

	fprintf(fp, ","J(exec_whitelist)"");
	dump_aclq(&box->acl_exec, dump_quoted);
	fprintf(fp, ","J(read_whitelist)"");
	dump_aclq(&box->acl_read, dump_quoted);
	fprintf(fp, ","J(write_whitelist)"");
	dump_aclq(&box->acl_write, dump_quoted);
	/*"J(TODO)"network whitelist */
	fprintf(fp, "}");
}

static void dump_process(syd_process_t *p)
{
	int r;
	struct proc_statinfo info;

	assert(p != NULL);

	fprintf(fp, "{"
		J(flag_SYDBOX_CHILD)"%s,"
		J(flag_STARTUP)"%s,"
		J(flag_IGNORE_ONE_SIGSTOP)"%s,"
		J(flag_READY)"%s,"
		J(flag_IN_SYSCALL)"%s,"
		J(flag_DENY_SYSCALL)"%s,"
		J(flag_STOP_AT_SYSEXIT)"%s,"
#ifdef CLONE_VM
		J(flag_CLONE_VM)"%s,"
#endif
#ifdef CLONE_FS
		J(flag_CLONE_FS)"%s,"
#endif
#ifdef CLONE_FILES
		J(flag_CLONE_FILES)"%s,"
#endif
#ifdef CLONE_SIGHAND
		J(flag_CLONE_SIGHAND)"%s,"
#endif
#ifdef CLONE_PTRACE
		J(flag_CLONE_PTRACE)"%s,"
#endif
#ifdef CLONE_VFORK
		J(flag_CLONE_VFORK)"%s,"
#endif
#ifdef CLONE_PARENT
		J(flag_CLONE_PARENT)"%s,"
#endif
#ifdef CLONE_THREAD
		J(flag_CLONE_THREAD)"%s,"
#endif
#ifdef CLONE_NEWNS
		J(flag_CLONE_NEWNS)"%s,"
#endif
#ifdef CLONE_SYSVSEM
		J(flag_CLONE_SYSVSEM)"%s,"
#endif
#ifdef CLONE_SETTLS
		J(flag_CLONE_SETTLS)"%s,"
#endif
#ifdef CLONE_PARENT_SETTID
		J(flag_CLONE_PARENT_SETTID)"%s,"
#endif
#ifdef CLONE_CHILD_CLEARTID
		J(flag_CLONE_CHILD_CLEARTID)"%s,"
#endif
#ifdef CLONE_DETACHED
		J(flag_CLONE_DETACHED)"%s,"
#endif
#ifdef CLONE_UNTRACED
		J(flag_CLONE_UNTRACED)"%s,"
#endif
#ifdef CLONE_CHILD_SETTID
		J(flag_CLONE_CHILD_SETTID)"%s,"
#endif
#ifdef CLONE_NEWUTS
		J(flag_CLONE_NEWUTS)"%s,"
#endif
#ifdef CLONE_NEWIPC
		J(flag_CLONE_NEWIPC)"%s,"
#endif
#ifdef CLONE_NEWUSER
		J(flag_CLONE_NEWUSER)"%s,"
#endif
#ifdef CLONE_NEWPID
		J(flag_CLONE_NEWPID)"%s,"
#endif
#ifdef CLONE_NEWNET
		J(flag_CLONE_NEWNET)"%s,"
#endif
#ifdef CLONE_IO
		J(flag_CLONE_IO)"%s,"
#endif
		J(ref_CLONE_THREAD)"%d,"
		J(ref_CLONE_FS)"%d,"
		J(ref_CLONE_FILES)"%d,"
		J(ppid)"%d,"
		J(comm)"\"%s\","
		J(cwd)"\"%s\"," /*"J(FIXME)"quote */
		J(syscall_no)"%lu,"
		J(syscall_abi)"%d,"
		J(syscall_name)"\"%s\"",
		J_BOOL(p->flags & SYD_SYDBOX_CHILD),
		J_BOOL(p->flags & SYD_STARTUP),
		J_BOOL(p->flags & SYD_IGNORE_ONE_SIGSTOP),
		J_BOOL(p->flags & SYD_READY),
		J_BOOL(p->flags & SYD_IN_SYSCALL),
		J_BOOL(p->flags & SYD_DENY_SYSCALL),
		J_BOOL(p->flags & SYD_STOP_AT_SYSEXIT),
#ifdef CLONE_VM
		J_BOOL(p->clone_flags & CLONE_VM),
#endif
#ifdef CLONE_FS
		J_BOOL(p->clone_flags & CLONE_FS),
#endif
#ifdef CLONE_FILES
		J_BOOL(p->clone_flags & CLONE_FILES),
#endif
#ifdef CLONE_SIGHAND
		J_BOOL(p->clone_flags & CLONE_SIGHAND),
#endif
#ifdef CLONE_PTRACE
		J_BOOL(p->clone_flags & CLONE_PTRACE),
#endif
#ifdef CLONE_VFORK
		J_BOOL(p->clone_flags & CLONE_VFORK),
#endif
#ifdef CLONE_PARENT
		J_BOOL(p->clone_flags & CLONE_PARENT),
#endif
#ifdef CLONE_THREAD
		J_BOOL(p->clone_flags & CLONE_THREAD),
#endif
#ifdef CLONE_NEWNS
		J_BOOL(p->clone_flags & CLONE_NEWNS),
#endif
#ifdef CLONE_SYSVSEM
		J_BOOL(p->clone_flags & CLONE_SYSVSEM),
#endif
#ifdef CLONE_SETTLS
		J_BOOL(p->clone_flags & CLONE_SETTLS),
#endif
#ifdef CLONE_PARENT_SETTID
		J_BOOL(p->clone_flags & CLONE_PARENT_SETTID),
#endif
#ifdef CLONE_CHILD_CLEARTID
		J_BOOL(p->clone_flags & CLONE_CHILD_CLEARTID),
#endif
#ifdef CLONE_DETACHED
		J_BOOL(p->clone_flags & CLONE_DETACHED),
#endif
#ifdef CLONE_UNTRACED
		J_BOOL(p->clone_flags & CLONE_UNTRACED),
#endif
#ifdef CLONE_CHILD_SETTID
		J_BOOL(p->clone_flags & CLONE_CHILD_SETTID),
#endif
#ifdef CLONE_NEWUTS
		J_BOOL(p->clone_flags & CLONE_NEWUTS),
#endif
#ifdef CLONE_NEWIPC
		J_BOOL(p->clone_flags & CLONE_NEWIPC),
#endif
#ifdef CLONE_NEWUSER
		J_BOOL(p->clone_flags & CLONE_NEWUSER),
#endif
#ifdef CLONE_NEWPID
		J_BOOL(p->clone_flags & CLONE_NEWPID),
#endif
#ifdef CLONE_NEWNET
		J_BOOL(p->clone_flags & CLONE_NEWNET),
#endif
#ifdef CLONE_IO
		J_BOOL(p->clone_flags & CLONE_IO),
#endif
		p->shm.clone_thread ? p->shm.clone_thread->refcnt : 0,
		p->shm.clone_fs ? p->shm.clone_fs->refcnt : 0,
		p->shm.clone_files ? p->shm.clone_files->refcnt : 0,
		p->ppid,
		p->shm.clone_thread ? p->shm.clone_thread->comm : "nil",
		p->shm.clone_fs ? p->shm.clone_fs->cwd : "nil",
		p->sysnum,
		p->abi,
		p->sysname);

	fprintf(fp, ","J(proc_stat)"");
	if (!(flags & DUMP_PROCFS))
		fprintf(fp, "null");
	else {
		r = proc_stat(p->pid, &info);
		if (r < 0)
			dump_errno(-r);
		else
			dump_proc_statinfo(&info);
	}

	fprintf(fp, ","J(sandbox)"");
	if (!(flags & DUMP_SANDBOX) || !p->shm.clone_thread)
		fprintf(fp, "null");
	else
		dump_sandbox(p->shm.clone_thread->box);

	fprintf(fp, "}");
}

static void dump_intr(int sig)
{
	fclose(fp);
}

static int dump_init(void)
{
	int r, fd;
	const char *pathname;
	struct sigaction sa;

	if (!nodump)
		return -EINVAL;
	if (nodump > 0)
		return 0;

	pathname = getenv(DUMP_ENV);
	if (!pathname) {
		nodump = 0;
		return -EINVAL;
	}
	fd = open(pathname, O_WRONLY);
	if (fd < 0)
		die_errno("open_dump");
	fp = fdopen(fd, "w");
	if (!fp)
		die_errno("fdopen_dump");
	nodump = 1;

	sa.sa_handler = dump_intr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
#define x_sigaction(sig, act, oldact) \
	do { \
		r = sigaction((sig), (act), (oldact)); \
		if (r < 0) \
			die_errno("sigaction"); \
	} while (0)

	x_sigaction(SIGABRT, &sa, NULL);
	x_sigaction(SIGHUP, &sa, NULL);
	x_sigaction(SIGINT, &sa, NULL);
	x_sigaction(SIGQUIT, &sa, NULL);
	x_sigaction(SIGPIPE, &sa, NULL);
	x_sigaction(SIGTERM, &sa, NULL);

	dump_format();
	dump_cycle();
	return 0;
}

void dump(enum dump what, ...)
{
	va_list ap;

	if (dump_init() != 0)
		return;
	if (what == DUMP_INIT)
		return;
	if (what == DUMP_CLOSE) {
		dump_close();
		return;
	}
	if (what == DUMP_FLUSH) {
		dump_flush();
		return;
	}

	va_start(ap, what);

	if (what == DUMP_STATE_CHANGE) {
		pid_t pid = va_arg(ap, pid_t);
		int status = va_arg(ap, int);
		int wait_errno = va_arg(ap, int);
		syd_process_t *p;

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d,"
			J(status),
			id++, DUMP_STATE_CHANGE, "state_change", pid);

		if (wait_errno == 0)
			dump_wait_status(status);
		else
			dump_errno(wait_errno);

		p = lookup_process(pid);
		fprintf(fp, ","J(process));
		if (!p)
			fprintf(fp, "null");
		else
			dump_process(p);
		fprintf(fp, "}");
	} else if (what == DUMP_PTRACE_EXECVE) {
		pid_t pid = va_arg(ap, pid_t);
		long old_tid = va_arg(ap, long);
		syd_process_t *p, *t;

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d,"
			J(old_tid)"%ld",
			id++, DUMP_PTRACE_EXECVE, "ptrace_execve",
			pid, old_tid);

		p = lookup_process(pid);
		fprintf(fp, ","J(process));
		if (!p)
			fprintf(fp, "null");
		else
			dump_process(p);

		fprintf(fp, ","J(execve_thread));
		if (pid == old_tid)
			fprintf(fp, "0");
		else if (!(t = lookup_process(old_tid)))
			fprintf(fp, "null");
		else
			dump_process(t);
		fprintf(fp, "}");
	} else if (what == DUMP_PTRACE_STEP) {
		int sig = va_arg(ap, int);
		int ptrace_errno = va_arg(ap, int);
		enum syd_step step = va_arg(ap, enum syd_step);
		const char *step_name = va_arg(ap, const char *);
		syd_process_t *p = va_arg(ap, syd_process_t *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(step)"%u,"
			J(step_name)"\"%s\","
			J(sig)"%d,"
			J(pid)"%d",
			id++, DUMP_PTRACE_STEP, "ptrace_step",
			step, step_name, sig, p->pid);

		fprintf(fp, ","J(ptrace));
		dump_errno(ptrace_errno);

		fprintf(fp, ","J(process));
		dump_process(p);

		fprintf(fp, "}");
	} else if (what == DUMP_THREAD_NEW) {
		syd_process_t *t = va_arg(ap, syd_process_t *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d",
			id++, DUMP_THREAD_NEW, "thread_new", t->pid);

		fprintf(fp, ","J(process));
		dump_process(t);

		fprintf(fp, "}");
	} else {
		abort();
	}

	va_end(ap);
	dump_cycle();
}
