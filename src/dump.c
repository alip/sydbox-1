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
static unsigned long flags = DUMPF_PROCFS|DUMPF_SYSARGV;
static unsigned long long id;

struct sysdump {
	const char *name;
	int argf[PINK_MAX_ARGS];
};

#if 0
static const struct sysdump syscall_dump[] = {
};
#endif

/* I know, I am so damn lazy... */
#define pink_wrap(prototype, func, rtype, ...) \
	rtype __real_pink_##prototype ; \
	rtype __wrap_pink_##prototype \
	{ \
		rtype r; \
		int save_errno; \
		\
		r = __real_pink_##func(__VA_ARGS__); \
		\
		save_errno = errno; \
		dump(DUMP_PINK, #func, r, save_errno, __VA_ARGS__); \
		errno = save_errno; \
		\
		return r; \
	}

pink_wrap(trace_resume(pid_t pid, int sig), trace_resume, int, pid, sig)
pink_wrap(trace_kill(pid_t tid, pid_t tgid, int sig), trace_kill, int, tid, tgid, sig)
pink_wrap(trace_singlestep(pid_t pid, int sig), trace_singlestep, int, pid, sig)
pink_wrap(trace_syscall(pid_t pid, int sig), trace_syscall, int, pid, sig)
pink_wrap(trace_geteventmsg(pid_t pid, unsigned long *data), trace_geteventmsg, int, pid, data)
pink_wrap(trace_get_regs(pid_t pid, void *regs), trace_get_regs, int, pid, regs)
pink_wrap(trace_get_regset(pid_t pid, void *regset, int n_type), trace_get_regset, int, pid, regset, n_type)
pink_wrap(trace_set_regs(pid_t pid, const void *regs), trace_set_regs, int, pid, regs)
pink_wrap(trace_set_regset(pid_t pid, const void *regset, int n_type), trace_set_regset, int, pid, regset, n_type)
pink_wrap(trace_get_siginfo(pid_t pid, void *info), trace_get_siginfo, int, pid, info)
pink_wrap(trace_setup(pid_t pid, int options), trace_setup, int, pid, options)
pink_wrap(trace_sysemu(pid_t pid, int sig), trace_sysemu, int, pid, sig)
pink_wrap(trace_sysemu_singlestep(pid_t pid, int sig), trace_sysemu_singlestep, int, pid, sig)
pink_wrap(trace_attach(pid_t pid), trace_attach, int, pid)
pink_wrap(trace_detach(pid_t pid, int sig), trace_detach, int, pid, sig)
pink_wrap(trace_seize(pid_t pid, int options), trace_seize, int, pid, options)
pink_wrap(trace_interrupt(pid_t pid), trace_interrupt, int, pid)
pink_wrap(trace_listen(pid_t pid), trace_listen, int, pid)

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

static void dump_null(void)
{
	fprintf(fp, "null");
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
	const char *name;

	fprintf(fp, "{"
		J(value)"%d,"
		J(WIFEXITED)"%s,"
		J(WIFSIGNALED)"%s,"
		J(WCOREDUMP)"%s,"
		J(WIFSTOPPED)"%s,"
		J(WIFCONTINUED)"%s,"
		J(WEXITSTATUS)"%u,"
		J(WTERMSIG)"%d,"
		J(WSTOPSIG)"%d",
		status,
		J_BOOL(WIFEXITED(status)),
		J_BOOL(WIFSIGNALED(status)),
		J_BOOL(WIFSIGNALED(status) && WCOREDUMP(status)),
		J_BOOL(WIFSTOPPED(status)),
		J_BOOL(WIFCONTINUED(status)),
		WIFEXITED(status) ? WEXITSTATUS(status) : 0,
		WIFSIGNALED(status) ? WTERMSIG(status) : 0,
		WIFSTOPPED(status) ? WSTOPSIG(status) : 0);

	fprintf(fp, ","J(WTERMSIG_name));
	if(WIFSIGNALED(status)) {
		name = pink_name_signal(WTERMSIG(status), 0);
		if (name == NULL)
			dump_null();
		else
			fprintf(fp, "\"%s\"", name);
	} else {
		dump_null();
	}

	fprintf(fp, ","J(WSTOPSIG_name));
	if(WIFSTOPPED(status)) {
		name = pink_name_signal(WSTOPSIG(status), 0);
		if (name == NULL)
			dump_null();
		else
			fprintf(fp, "\"%s\"", name);
	} else {
		dump_null();
	}

	fprintf(fp, "}");
}

static void dump_ptrace(pid_t pid, int status)
{
	enum pink_event pink_event = pink_event_decide(status);
	const char *name = pink_name_event(pink_event);
	int r = 0;
	unsigned long msg;

	fprintf(fp, "{"J(value)"%u", pink_event);

	fprintf(fp, ","J(name));
	if (name)
		fprintf(fp, "\"%s\"", name);
	else
		dump_null();

	fprintf(fp, ","J(msg));
	switch (pink_event) {
	case PINK_EVENT_EXEC:
	case PINK_EVENT_FORK:
	case PINK_EVENT_VFORK:
	case PINK_EVENT_CLONE:
	case PINK_EVENT_VFORK_DONE:
	case PINK_EVENT_SECCOMP:
		r = __real_pink_trace_geteventmsg(pid, &msg);
		if (r < 0)
			dump_errno(-r);
		else
			fprintf(fp, "%lu", msg);
		break;
	default:
		dump_null();
		break;
	}

	fprintf(fp, ","J(syscall));
	if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP|0x80)) {
		struct pink_regset *regset = NULL;

		r = pink_regset_alloc(&regset);
		if (r < 0) {
			dump_errno(-r);
			goto out;
		}
		r = pink_regset_fill(pid, regset);
		if (r < 0) {
			dump_errno(-r);
			goto out;
		}

		short abi;
		pink_read_abi(pid, regset, &abi);

		fprintf(fp, "{"
			J(abi)"%u,"J(abi_wordsize)"%zu",
			abi, pink_abi_wordsize(abi));

		long sysnum;
		const char *sysname = NULL;

		pink_read_syscall(pid, regset, &sysnum);
		fprintf(fp, ","J(value)"%ld", sysnum);

		fprintf(fp, ","J(name));
		sysname = pink_name_syscall(sysnum, abi);
		if (sysname != NULL)
			fprintf(fp, "\"%s\"", sysname);
		else
			dump_null();

		long retval;
		int error;

		fprintf(fp, ","J(retval));
		pink_read_retval(pid, regset, &retval, &error);
		fprintf(fp, "{"J(value)"%ld", retval);
		fprintf(fp, ","J(error)); dump_errno(error);
		fprintf(fp, "}");

		unsigned i;
		long argval[PINK_MAX_ARGS];

		for (i = 0; i < PINK_MAX_ARGS; i++)
			pink_read_argument(pid, regset, i, &argval[i]);

		fprintf(fp, ","J(argv)"[");
		for (i = 0; i < PINK_MAX_ARGS; i++) {
			if (i > 0)
				fprintf(fp, ",");
			fprintf(fp, "%ld", argval[i]);
		}
		fprintf(fp, "]");

		fprintf(fp, "}");
out:
		if (regset)
			pink_regset_free(regset);
	} else {
		dump_null();
	}

	fprintf(fp, "}");
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

static void dump_pink(const char *name, int retval, int save_errno, pid_t pid, va_list ap)
{
	fprintf(fp, "{"
		J(name)"\"%s\","
		J(return)"%d,"
		J(errno)"%d,"
		J(pid)"%d",
		name, retval, save_errno, pid);

	fprintf(fp, "}");
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

static void dump_process(pid_t pid)
{
	int r;
	struct proc_statinfo info;
	syd_process_t *p;

	fprintf(fp, "{"J(pid)"%d", pid);

	if (pid <= 0) {
		fprintf(fp, "}");
		return;
	}

	fprintf(fp, ","J(stat));
	if (flags & DUMPF_PROCFS) {
		r = proc_stat(pid, &info);
		if (r < 0)
			dump_errno(-r);
		else
			dump_proc_statinfo(&info);
	} else {
		dump_null();
	}

	fprintf(fp, ","J(syd));
	p = lookup_process(pid);
	if (!p) {
		dump_null();
		fprintf(fp, "}");
		return;
	}

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

	fprintf(fp, ","J(regset)"");
	/* TODO: if (flags & DUMP_PTRACE_REGSET) */
	dump_null();

	fprintf(fp, ","J(sandbox)"");
	if (!(flags & DUMPF_SANDBOX) || !p->shm.clone_thread)
		dump_null();
	else
		dump_sandbox(p->shm.clone_thread->box);

	fprintf(fp, "}}");
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

	if (what == DUMP_WAIT) {
		pid_t pid = va_arg(ap, pid_t);
		int status = va_arg(ap, int);
		int wait_errno = va_arg(ap, int);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d",
			id++, DUMP_WAIT, "wait", pid);

		fprintf(fp, ","J(status));
		if (wait_errno == 0)
			dump_wait_status(status);
		else
			dump_errno(wait_errno);

		fprintf(fp, ","J(ptrace));
		if (wait_errno == 0)
			dump_ptrace(pid, status);
		else
			dump_errno(wait_errno);

		fprintf(fp, ","J(process));
		dump_process(pid);

		fprintf(fp, "}");
	} else if (what == DUMP_PINK) {
		const char *name = va_arg(ap, const char *);
		int retval = va_arg(ap, int);
		int save_errno = va_arg(ap, int);
		pid_t pid = va_arg(ap, pid_t);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d",
			id++, DUMP_PINK, "pink", pid);

		fprintf(fp, ","J(pink));
		dump_pink(name, retval, save_errno, pid, ap);

		fprintf(fp, "}");
#if 0
	} else if (what == DUMP_PTRACE_EXECVE) {
		pid_t pid = va_arg(ap, pid_t);
		long old_tid = va_arg(ap, long);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d,"
			J(old_tid)"%ld",
			id++, DUMP_PTRACE_EXECVE, "ptrace_execve",
			pid, old_tid);

		fprintf(fp, ","J(process));
		dump_process(pid);

		fprintf(fp, ","J(execve_thread));
		if (pid == old_tid)
			fprintf(fp, "0");
		else
			dump_process(old_tid);

		fprintf(fp, "}");
	} else if (what == DUMP_PTRACE_CLONE) {
		pid_t pid = va_arg(ap, pid_t);
		long child_pid = va_arg(ap, long);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d,"
			J(child_pid)"%ld",
			id++, DUMP_PTRACE_CLONE, "ptrace_clone",
			pid, child_pid);

		fprintf(fp, ","J(process));
		dump_process(pid);

		fprintf(fp, ","J(child));
		dump_process(child_pid);

		fprintf(fp, "}");
	} else if (what == DUMP_PTRACE_STEP) {
		pid_t pid = va_arg(ap, pid_t);
		int sig = va_arg(ap, int);
		int ptrace_errno = va_arg(ap, int);
		enum syd_step step = va_arg(ap, enum syd_step);
		const char *step_name = va_arg(ap, const char *);

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(step)"%u,"
			J(step_name)"\"%s\","
			J(sig)"%d,"
			J(pid)"%d",
			id++, DUMP_PTRACE_STEP, "ptrace_step",
			step, step_name, sig, pid);

		fprintf(fp, ","J(ptrace));
		dump_errno(ptrace_errno);

		fprintf(fp, ","J(process));
		dump_process(pid);

		fprintf(fp, "}");
#endif
	} else if (what == DUMP_THREAD_NEW || what == DUMP_THREAD_FREE) {
		pid_t pid = va_arg(ap, pid_t);
		const char *event_name;

		if (what == DUMP_THREAD_NEW)
			event_name = "thread_new";
		else if (what == DUMP_THREAD_FREE)
			event_name = "thread_free";

		fprintf(fp, "{"
			J(id)"%llu,"
			J(event)"%u,"
			J(event_name)"\"%s\","
			J(pid)"%d",
			id++, what, event_name, pid);

		fprintf(fp, ","J(process));
		dump_process(pid);
		fprintf(fp, "}");
	} else {
		abort();
	}

	va_end(ap);
	dump_cycle();
}
