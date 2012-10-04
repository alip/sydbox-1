/*
 * sydbox/sydbox-magic.c
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "log.h"
#include "proc.h"
#include "strtable.h"

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

static bool cont_one(struct pink_easy_process *proc, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(proc);
	pink_easy_process_detach(proc);
	return true;
}

static bool kill_one(struct pink_easy_process *proc, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(proc);
	int fatal_sig = PTR_TO_INT(userdata);
	pink_easy_process_kill(proc, fatal_sig);
	return true;
}

void cont_all(void)
{
	unsigned count;
	struct pink_easy_process_list *list;

	list = pink_easy_context_get_process_list(sydbox->ctx);
	count = pink_easy_process_list_walk(list, cont_one, NULL);
	log_info("resumed %u process%s", count, count > 1 ? "es" : "");
}

void abort_all(int fatal_sig)
{
	unsigned count;
	struct pink_easy_process_list *list;

	if (!sydbox || !sydbox->ctx)
		return;

	list = pink_easy_context_get_process_list(sydbox->ctx);
	switch (sydbox->config.abort_decision) {
	case ABORT_CONTALL:
		count = pink_easy_process_list_walk(list, cont_one, NULL);
		fprintf(stderr, PACKAGE": resumed %u process%s\n", count,
			count > 1 ? "es" : "");
		break;
	case ABORT_KILLALL:
		count = pink_easy_process_list_walk(list, kill_one,
						    INT_TO_PTR(fatal_sig));
		fprintf(stderr, PACKAGE": killed %u process%s\n", count,
			count > 1 ? "es" : "");
		break;
	}
}

PINK_GCC_ATTR((format (printf, 2, 0)))
static void report(struct pink_easy_process *current, const char *fmt,
		   va_list ap)
{
	char *cmdline;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	log_access_v("-- Access Violation! --");
	log_access_v("process id=%lu (abi=%d name:`%s')", (unsigned long)tid,
		     abi, data->comm);
	log_access_v("cwd: `%s'", data->cwd);

	if (proc_cmdline(tid, 128, &cmdline) == 0) {
		log_access_v("cmdline: `%s'", cmdline);
		free(cmdline);
	}

	log_msg_va(1, fmt, ap);
}

int deny(struct pink_easy_process *current, int err_no)
{
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	data->deny = true;
	data->retval = errno2retval(err_no);

	log_access("%s[%lu:%u] return code:%ld errno:%s",
		   data->comm,
		   (unsigned long)tid, abi,
		   data->retval,
		   errno_to_string(err_no));

	if (!pink_write_syscall(tid, abi, PINK_SYSCALL_INVALID)) {
		if (errno != ESRCH) {
			log_warning("write syscall:%#x failed (errno:%d %s)",
				    PINK_SYSCALL_INVALID,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("write syscall:%#x failed (errno:%d %s)",
			  PINK_SYSCALL_INVALID,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	return 0;
}

int restore(struct pink_easy_process *current)
{
	int retval, error;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	log_trace("%s[%lu:%d] sys:%s()",
		  data->comm, (unsigned long)tid, abi,
		  pink_syscall_name(data->sno, abi));

	/* Restore system call number */
	if (!pink_write_syscall(tid, abi, data->sno)) {
		if (errno == ESRCH) {
			log_trace("write syscall:%#lx failed (errno:%d %s)",
				  data->sno, errno, strerror(errno));
			log_trace("drop process %s[%lu:%d]",
				  data->comm, (unsigned long)tid, abi);
			return PINK_EASY_CFLAG_DROP;
		}
		log_warning("write syscall:%#lx failed (errno:%d %s)",
			    data->sno, errno, strerror(errno));
		return panic(current);
	}

	/* Return the saved return value */
	if (data->retval < 0) { /* failure */
		retval = -1;
		error = -data->retval;
	} else { /* success */
		retval = data->retval;
		error = 0;
	}
	if (!pink_write_retval(tid, abi, retval, error)) {
		if (errno == ESRCH) {
			log_trace("write retval=%d and error=%s failed"
				  " (errno:%d %s)",
				  retval, errno_to_string(error),
				  errno, strerror(errno));
			log_trace("drop process %s[%lu:%d]",
				  data->comm, (unsigned long)tid, abi);
			return PINK_EASY_CFLAG_DROP;
		}

		log_warning("write retval=%d and error=%s failed"
			    " (errno:%d %s)",
			    retval, errno_to_string(error),
			    errno, strerror(errno));
		return panic(current);
	}

	return 0;
}

int panic(struct pink_easy_process *current)
{
	unsigned count;
	struct pink_easy_process_list *list;

	list = pink_easy_context_get_process_list(sydbox->ctx);

	switch (sydbox->config.panic_decision) {
	case PANIC_KILL:
		log_warning("panic! killing the guilty process");
		kill_one(current, INT_TO_PTR(SIGKILL));
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONT:
		log_warning("panic! resuming the guilty process");
		cont_one(current, NULL);
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONTALL:
		log_warning("panic! resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, NULL);
		log_warning("resumed %u process%s, exiting", count,
			    count > 1 ? "es" : "");
		break;
	case PANIC_KILLALL:
		log_warning("panic! killing all processes");
		count = pink_easy_process_list_walk(list, kill_one,
						    INT_TO_PTR(SIGKILL));
		log_warning("killed %u process%s, exiting", count,
			    count > 1 ? "es" : "");
		break;
	default:
		assert_not_reached();
	}

	/* exit */
	exit(sydbox->config.panic_exit_code > 0
	     ? sydbox->config.panic_exit_code
	     : sydbox->exit_code);
}

int violation(struct pink_easy_process *current, const char *fmt, ...)
{
	unsigned count;
	va_list ap;
	struct pink_easy_process_list *list;

	list = pink_easy_context_get_process_list(sydbox->ctx);
	sydbox->violation = true;

	va_start(ap, fmt);
	report(current, fmt, ap);
	va_end(ap);

	switch (sydbox->config.violation_decision) {
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		log_warning("killing the guilty process");
		kill_one(current, INT_TO_PTR(SIGKILL));
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONT:
		log_warning("resuming the guilty process");
		cont_one(current, NULL);
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONTALL:
		log_warning("resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, NULL);
		log_warning("resumed %u processes, exiting", count);
		break;
	case VIOLATION_KILLALL:
		log_warning("killing all processes");
		count = pink_easy_process_list_walk(list, kill_one,
						    INT_TO_PTR(SIGKILL));
		log_warning("killed %u processes, exiting", count);
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
