/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "proc.h"

static inline int errno2retval(void)
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
	return -errno;
}

static bool cont_one(struct pink_easy_process *proc, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(proc);
	int level = PTR_TO_INT(userdata);

	if (level < 0)
		fprintf(stderr, "resuming process:%lu\n", (unsigned long)tid);
	else
		log_msg(level, "resuming process:%lu", (unsigned long)tid);

	if (!pink_easy_process_resume(proc, 0) && errno != ESRCH) {
		if (level < 0)
			fprintf(stderr, "failed to resume process:%lu (errno:%d %s)\n",
					(unsigned long)tid, errno, strerror(errno));
		else
			log_msg(level, "failed to resume process:%lu (errno:%d %s)",
				(unsigned long)tid, errno, strerror(errno));
	}

	return true;
}

static bool kill_one(struct pink_easy_process *proc, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(proc);
	int level = PTR_TO_INT(userdata);

	if (level < 0)
		fprintf(stderr, "killing process:%lu\n", (unsigned long)tid);
	else
		log_msg(level, "killing process:%lu", (unsigned long)tid);

	if (pink_easy_process_kill(proc, SIGKILL) < 0 && errno != ESRCH) {
		if (level < 0)
			fprintf(stderr, "failed to kill process:%lu (errno:%d %s)\n",
					(unsigned long)tid, errno, strerror(errno));
		else
			log_msg(level, "failed to kill process:%lu (errno:%d %s)",
				(unsigned long)tid, errno, strerror(errno));
	}

	return true;
}

void cont_all(void)
{
	unsigned count;
	struct pink_easy_process_list *list = pink_easy_context_get_process_list(sydbox->ctx);

	count = pink_easy_process_list_walk(list, cont_one, INT_TO_PTR(LL_MESSAGE));
	info("resumed %u process%s", count, count > 1 ? "es" : "");
}

void abort_all(void)
{
	unsigned count;
	struct pink_easy_process_list *list = pink_easy_context_get_process_list(sydbox->ctx);

	switch (sydbox->config.abort_decision) {
	case ABORT_CONTALL:
		count = pink_easy_process_list_walk(list, cont_one, INT_TO_PTR(-1));
		fprintf(stderr, "resumed %u process%s\n", count, count > 1 ? "es" : "");
		break;
	case ABORT_KILLALL:
		count = pink_easy_process_list_walk(list, kill_one, INT_TO_PTR(-1));
		fprintf(stderr, "killed %u process%s\n", count, count > 1 ? "es" : "");
		break;
	default:
		break;
	}
}

PINK_GCC_ATTR((format (printf, 2, 0)))
static void report(struct pink_easy_process *current, const char *fmt, va_list ap)
{
	char *cmdline;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	warning("-- Access Violation! --");
	warning("process id:%lu (abi:%d name:\"%s\")", (unsigned long)tid, abi, data->comm);
	warning("cwd: `%s'", data->cwd);

	if (!proc_cmdline(tid, 128, &cmdline)) {
		warning("cmdline: `%s'", cmdline);
		free(cmdline);
	}

	log_msg_va(1, fmt, ap);
}

int deny(struct pink_easy_process *current)
{
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	data->deny = true;
	data->retval = errno2retval();

	if (!pink_write_syscall(tid, abi, PINK_SYSCALL_INVALID)) {
		if (errno != ESRCH) {
			warning("pink_write_syscall(%lu, %d, %u) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					PINK_SYSCALL_INVALID,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	return 0;
}

int restore(struct pink_easy_process *current)
{
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	/* Restore system call number */
	if (!pink_write_syscall(tid, abi, data->sno)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_write_syscall(%lu, %d, %s) failed (errno:%d %s)",
				(unsigned long)tid, abi,
				pink_syscall_name(data->sno, abi),
				errno, strerror(errno));
	}

	/* Return the saved return value */
	if (!pink_write_retval(tid, abi,
				(data->retval < 0) ? -1 : data->retval,
				(data->retval < 0) ? -data->retval : 0)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_write_retval(%lu, %d, %s) failed (errno:%d %s)",
				(unsigned long)tid, abi,
				pink_syscall_name(data->sno, abi),
				errno, strerror(errno));
	}

	return 0;
}

int panic(struct pink_easy_process *current)
{
	unsigned count;
	struct pink_easy_process_list *list = pink_easy_context_get_process_list(sydbox->ctx);

	switch (sydbox->config.panic_decision) {
	case PANIC_KILL:
		warning("panic! killing the guilty process");
		kill_one(current, INT_TO_PTR(LL_WARNING));
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONT:
		warning("panic! resuming the guilty process");
		cont_one(current, INT_TO_PTR(LL_WARNING));
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONTALL:
		warning("panic! resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, INT_TO_PTR(LL_WARNING));
		warning("resumed %u process%s, exiting", count, count > 1 ? "es" : "");
		break;
	case PANIC_KILLALL:
		warning("panic! killing all processes");
		count = pink_easy_process_list_walk(list, kill_one, INT_TO_PTR(LL_WARNING));
		warning("killed %u process%s, exiting", count, count > 1 ? "es" : "");
		break;
	default:
		abort();
	}

	/* exit */
	exit(sydbox->config.panic_exit_code > 0 ? sydbox->config.panic_exit_code : sydbox->exit_code);
}

int violation(struct pink_easy_process *current, const char *fmt, ...)
{
	unsigned count;
	va_list ap;
	struct pink_easy_process_list *list = pink_easy_context_get_process_list(sydbox->ctx);

	sydbox->violation = true;

	va_start(ap, fmt);
	report(current, fmt, ap);
	va_end(ap);

	switch (sydbox->config.violation_decision) {
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		warning("killing the guilty process");
		kill_one(current, UINT_TO_PTR(1));
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONT:
		warning("resuming the guilty process");
		cont_one(current, UINT_TO_PTR(1));
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONTALL:
		warning("resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, UINT_TO_PTR(1));
		warning("resumed %u processes, exiting", count);
		break;
	case VIOLATION_KILLALL:
		warning("killing all processes");
		count = pink_easy_process_list_walk(list, kill_one, UINT_TO_PTR(1));
		warning("killed %u processes, exiting", count);
		break;
	default:
		abort();
	}

	/* exit */
	if (sydbox->config.violation_exit_code > 0)
		exit(sydbox->config.violation_exit_code);
	else if (sydbox->config.violation_exit_code == 0)
		exit(128 + sydbox->config.violation_exit_code);
	exit(sydbox->exit_code);
}
