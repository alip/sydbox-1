/*
 * sydbox/panic.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <pinktrace/pink.h>
#include "log.h"
#include "proc.h"

static inline int errno2retval(int err_no)
{
#if 0
#warning pink_ptrace() handles this oddity!
	if (errno == EIO) {
		/* Quoting ptrace(2):
		 * There  was  an  attempt  to read from or write to an
		 * invalid area in the parent's or child's memory,
		 * probably because the area wasn't mapped or
		 * accessible. Unfortunately, under Linux, different
		 * variations of this fault will return EIO or EFAULT
		 * more or less arbitrarily.
		 */
		/* For consistency we change the errno to EFAULT here.
		 * Because it's usually what we actually want.
		 * For example:
		 * open(NULL, O_RDONLY) (returns: -1, errno: EFAULT)
		 * under ptrace, we may get errno: EIO
		 */
		return -EFAULT;
	}
#endif
	return -err_no;
}

void cont_all(void)
{
	syd_proc_t *node;

	SYD_FOREACH_PROCESS(node) {
		syd_trace_detach(node, 0);
	}
}

void kill_all(void)
{
	syd_proc_t *node;

	SYD_FOREACH_PROCESS(node) {
		syd_trace_kill(node, SIGKILL);
	}
}

void abort_all(int fatal_sig)
{
	syd_proc_t *node;

	if (!sydbox)
		return;

	switch (sydbox->config.abort_decision) {
	case ABORT_CONTALL:
		SYD_FOREACH_PROCESS(node) {
			syd_trace_detach(node, 0);
		}
		break;
	case ABORT_KILLALL:
		SYD_FOREACH_PROCESS(node) {
			syd_trace_kill(node, SIGKILL);
		}
		break;
	}
}

PINK_GCC_ATTR((format (printf, 2, 0)))
static void report(syd_proc_t *current, const char *fmt, va_list ap)
{
	char *cmdline;
	pid_t pid = GET_PID(current);

	log_context(NULL);

	log_access_v("-- Access Violation! --");
	log_access_v("proc: %s[%u] (parent:%u)",
		     current->comm, pid, current->ppid);
	log_access_v("cwd: `%s'", current->cwd);

	if (proc_cmdline(pid, 128, &cmdline) == 0) {
		log_access_v("cmdline: `%s'", cmdline);
		free(cmdline);
	}

	log_msg_va(1, fmt, ap);

	log_context(current);
}

int deny(syd_proc_t *current, int err_no)
{
	current->flags |= SYD_DENYSYSCALL | SYD_STOP_AT_SYSEXIT;
	current->retval = errno2retval(err_no);

	log_access("DENY retval:%ld errno:%d|%s|", current->retval,
		   err_no, pink_name_errno(err_no, 0));

	return syd_write_syscall(current, PINK_SYSCALL_INVALID);
}

int restore(syd_proc_t *current)
{
	int r;
	int retval, error;

	log_trace("RESTORE");

	/* restore system call number */
	if ((r = syd_write_syscall(current, current->sysnum)) < 0)
		return r;

	/* return the saved return value */
	if (current->retval < 0) { /* failure */
		retval = -1;
		error = -current->retval;
	} else { /* success */
		retval = current->retval;
		error = 0;
	}

	return syd_write_retval(current, retval, error);
}

int panic(syd_proc_t *current)
{
	switch (sydbox->config.panic_decision) {
	case PANIC_KILL:
		log_warning("PANIC_KILL");
		syd_trace_kill(current, SIGKILL);
		return -ESRCH;
	case PANIC_CONT:
		log_warning("PANIC_CONT");
		syd_trace_detach(current, 0);
		return -ESRCH;
	case PANIC_CONTALL:
		log_warning("PANIC_CONTALL");
		cont_all();
		break;
	case PANIC_KILLALL:
		log_warning("PANIC_KILLALL");
		kill_all();
		break;
	default:
		assert_not_reached();
	}

	/* exit */
	exit(sydbox->config.panic_exit_code > 0
	     ? sydbox->config.panic_exit_code
	     : sydbox->exit_code);
}

int violation(syd_proc_t *current, const char *fmt, ...)
{
	va_list ap;

	sydbox->violation = true;

	va_start(ap, fmt);
	report(current, fmt, ap);
	va_end(ap);

	switch (sydbox->config.violation_decision) {
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		log_warning("VIOLATION_KILL");
		syd_trace_kill(current, SIGKILL);
		return -ESRCH;
	case VIOLATION_CONT:
		log_warning("VIOLATION_CONT");
		syd_trace_detach(current, 0); /* FIXME: detach+seccomp fails! */
		return -ESRCH;
	case VIOLATION_CONTALL:
		log_warning("VIOLATION_CONTALL");
		cont_all();
		break;
	case VIOLATION_KILLALL:
		log_warning("VIOLATION_KILLALL");
		kill_all();
		break;
	default:
		assert_not_reached();
	}

	/* exit */
	if (sydbox->config.violation_exit_code > 0)
		exit(sydbox->config.violation_exit_code);
	else if (sydbox->config.violation_exit_code == 0)
		exit(128 + sydbox->config.violation_exit_code);
	exit(sydbox->exit_code);
}
