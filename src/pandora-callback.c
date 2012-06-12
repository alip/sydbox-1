/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Pandora's Box. pandora is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pandora is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "pandora-defs.h"

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "file.h"
#include "proc.h"

#ifndef NR_OPEN
#define NR_OPEN 1024
#endif

static int callback_child_error(pink_easy_child_error_t error)
{
	fprintf(stderr, "child error: %s (errno:%d %s)\n",
			pink_easy_child_strerror(error),
			errno, strerror(errno));
	return -1;
}

static void callback_error(const struct pink_easy_context *ctx, ...)
{
	va_list ap;
	const char *errctx;
	pid_t pid;
	pink_easy_error_t error;
	pink_easy_process_t *current;

	error = pink_easy_context_get_error(ctx);
	va_start(ap, ctx);

	switch (error) {
	case PINK_EASY_ERROR_CALLBACK_ABORT:
	case PINK_EASY_ERROR_WAIT:
		fatal("error: %s (errno:%d %s)\n",
				pink_easy_strerror(error),
				errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_ALLOC:
	case PINK_EASY_ERROR_FORK:
		errctx = va_arg(ap, const char *);
		fatal("error: %s: %s (errno:%d %s)\n",
				pink_easy_strerror(error),
				errctx, errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_ATTACH:
		pid = va_arg(ap, pid_t);
		fatal("error: %s (process:%lu errno:%d %s)\n",
				pink_easy_strerror(error),
				(unsigned long)pid,
				errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_TRACE:
	case PINK_EASY_ERROR_PROCESS:
		current = va_arg(ap, pink_easy_process_t *);
		errctx = va_arg(ap, const char *);
		if (error == PINK_EASY_ERROR_TRACE) { /* errno is set! */
			fatal("error: %s (ctx:%s process:%lu [%s] errno:%d %s)",
					pink_easy_strerror(error), errctx,
					(unsigned long)pink_easy_process_get_pid(current),
					pink_bitness_name(pink_easy_process_get_bitness(current)),
					errno, strerror(errno));
		} else { /* if (error == PINK_EASY_ERROR_PROCESS */
			fatal("error: %s (process:%lu [%s])",
					pink_easy_strerror(error),
					(unsigned long)pink_easy_process_get_pid(current),
					pink_bitness_name(pink_easy_process_get_bitness(current)));
		}
		break;
	default:
		fatal("error: unknown:%u\n", error);
		break;
	}

	va_end(ap);
}

static void callback_startup(PINK_GCC_ATTR((unused)) const pink_easy_context_t *ctx,
		pink_easy_process_t *current, pink_easy_process_t *parent)
{
	int r;
	pid_t pid;
	pink_bitness_t bit;
	char *cwd, *comm;
	struct snode *node, *newnode;
	proc_data_t *data, *pdata;
	sandbox_t *inherit;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
	data = xcalloc(1, sizeof(proc_data_t));

	if (parent == NULL) {
		bool attached = pink_easy_process_is_attached(current);
		if (attached) {
			/* Figure out process name */
			if ((r = proc_comm(pid, &comm))) {
				warning("failed to read the name of process:%lu [%s] (errno:%d %s)",
						(unsigned long)pid, pink_bitness_name(bit),
						-r, strerror(-r));
				comm = xstrdup("???");
			}

			/* Figure out the current working directory */
			if ((r = proc_cwd(pid, &cwd))) {
				warning("failed to get working directory of the initial "
						"process:%lu [%s name:\"%s\"] (errno:%d %s)",
						(unsigned long)pid, pink_bitness_name(bit), comm,
						-r, strerror(-r));
				free(data);
				panic(current);
				return;
			}

			info("initial process:%lu [%s name:\"%s\" cwd:\"%s\"]",
					(unsigned long)pid, pink_bitness_name(bit),
					comm, cwd);
		} else {
			cwd = xgetcwd();
			comm = pandora->program_invocation_name;
			pandora->program_invocation_name = NULL;
		}

		pandora->eldest = pid;
		inherit = &pandora->config.child;
	} else {
		pdata = (proc_data_t *)pink_easy_process_get_userdata(parent);
		comm = xstrdup(pdata->comm);
		cwd = xstrdup(pdata->cwd);

		info("new process:%lu [%s name:\"%s\" cwd:\"%s\"]",
				(unsigned long)pid, pink_bitness_name(bit),
				comm, cwd);
		info("parent process:%lu [%s name:\"%s\" cwd:\"%s\"]",
				(unsigned long)pink_easy_process_get_pid(parent),
				pink_bitness_name(pink_easy_process_get_bitness(parent)),
				comm, cwd);

		inherit = &pdata->config;
	}

	/* Copy the configuration */
	data->config.sandbox_exec = inherit->sandbox_exec;
	data->config.sandbox_read = inherit->sandbox_read;
	data->config.sandbox_write = inherit->sandbox_write;
	data->config.sandbox_sock = inherit->sandbox_sock;
	data->config.magic_lock = inherit->magic_lock;
	data->comm = comm;
	data->cwd = cwd;

	/* Copy the lists  */
#define SLIST_COPY_ALL(var, head, field, newhead, newvar, copydata)	\
	do {								\
		SLIST_INIT(newhead);					\
		SLIST_FOREACH(var, head, field) {			\
			newvar = xcalloc(1, sizeof(struct snode));	\
			newvar->data = copydata(var->data);		\
			SLIST_INSERT_HEAD(newhead, newvar, field);	\
		}							\
	} while (0)

	SLIST_COPY_ALL(node, &inherit->whitelist_exec, up, &data->config.whitelist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_read, up, &data->config.whitelist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_write, up, &data->config.whitelist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_sock_bind, up, &data->config.whitelist_sock_bind, newnode, sock_match_xdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_sock_connect, up, &data->config.whitelist_sock_connect, newnode, sock_match_xdup);

	SLIST_COPY_ALL(node, &inherit->blacklist_exec, up, &data->config.blacklist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_read, up, &data->config.blacklist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_write, up, &data->config.blacklist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_sock_bind, up, &data->config.blacklist_sock_bind, newnode, sock_match_xdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_sock_connect, up, &data->config.blacklist_sock_connect, newnode, sock_match_xdup);
#undef SLIST_COPY_ALL

	if (pandora->config.whitelist_per_process_directories) {
#define SLIST_ALLOW_PID(var, head, field, id)							\
		do {										\
			var = xcalloc(1, sizeof(struct snode));					\
			xasprintf((char **)&var->data, "/proc/%lu/***", (unsigned long)id);	\
			SLIST_INSERT_HEAD(head, var, up);					\
		} while (0)
		SLIST_ALLOW_PID(newnode, &data->config.whitelist_read, up, pid);
		SLIST_ALLOW_PID(newnode, &data->config.whitelist_write, up, pid);
#undef SLIST_ALLOW_PID
	}

	/* Create the fd -> address hash table */
	if ((r = hashtable_create(NR_OPEN, 1, &data->sockmap)) < 0) {
		errno = -r;
		die_errno(-1, "hashtable_create");
	}

	pink_easy_process_set_userdata(current, data, free_proc);
}

static int callback_cleanup(PINK_GCC_ATTR((unused)) const pink_easy_context_t *ctx)
{
	if (pandora->violation) {
		if (pandora->config.violation_exit_code > 0)
			return pandora->config.violation_exit_code;
		else if (!pandora->config.violation_exit_code)
			return 128 + pandora->exit_code;
	}
	return pandora->exit_code;
}

static int callback_exit(PINK_GCC_ATTR((unused)) const pink_easy_context_t *ctx,
		pid_t pid, int status)
{
	if (pid == pandora->eldest) {
		/* Eldest child, keep return code */
		if (WIFEXITED(status)) {
			pandora->exit_code = WEXITSTATUS(status);
			message("initial process:%lu exited with code:%d (status:%#x)",
					(unsigned long)pid, pandora->exit_code,
					(unsigned)status);
		}
		else if (WIFSIGNALED(status)) {
			pandora->exit_code = 128 + WTERMSIG(status);
			message("initial process:%lu was terminated with signal:%d (status:%#x)",
					(unsigned long)pid, pandora->exit_code - 128,
					(unsigned)status);
		}
		else {
			warning("initial process:%lu exited with unknown status:%#x",
					(unsigned long)pid, (unsigned)status);
			warning("don't know how to determine exit code");
		}
	}
	else {
		if (WIFEXITED(status))
			info("process:%lu exited with code:%d (status:%#x)",
					(unsigned long)pid,
					WEXITSTATUS(status),
					(unsigned)status);
		else if (WIFSIGNALED(status))
			info("process:%lu exited was terminated with signal:%d (status:%#x)",
					(unsigned long)pid,
					WTERMSIG(status),
					(unsigned)status);
		else
			warning("process:%lu exited with unknown status:%#x",
					(unsigned long)pid, (unsigned)status);
	}

	return 0;
}

static int callback_exec(PINK_GCC_ATTR((unused)) const pink_easy_context_t *ctx,
		pink_easy_process_t *current,
		PINK_GCC_ATTR((unused)) pink_bitness_t orig_bitness)
{
	int e, r;
	char *comm;
	const char *match;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.magic_lock == LOCK_PENDING) {
		info("locking magic commands for process:%lu [%s name:\"%s\" cwd:\"%s\"]",
				(unsigned long)pid,
				pink_bitness_name(bit),
				data->comm, data->cwd);
		data->config.magic_lock = LOCK_SET;
	}

	if (pandora->skip_initial_exec) {
		/* Initial execve was successful, let the tracing begin! */
		pandora->skip_initial_exec = false;
		return 0;
	}

	if (!data->abspath) {
		/* Nothing left to do */
		return 0;
	}

	/* kill_if_match and resume_if_match */
	r = 0;
	if (box_match_path(data->abspath, &pandora->config.exec_kill_if_match, &match)) {
		warning("kill_if_match pattern `%s' matches execve path `%s'", match, data->abspath);
		warning("killing process:%lu [%s cwd:\"%s\"]", (unsigned long)pid, pink_bitness_name(bit), data->cwd);
		if (pink_easy_process_kill(current, SIGKILL) < 0)
			warning("failed to kill process:%lu (errno:%d %s)", (unsigned long)pid, errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}
	else if (box_match_path(data->abspath, &pandora->config.exec_resume_if_match, &match)) {
		warning("resume_if_match pattern `%s' matches execve path `%s'", match, data->abspath);
		warning("resuming process:%lu [%s cwd:\"%s\"]", (unsigned long)pid, pink_bitness_name(bit), data->cwd);
		if (!pink_easy_process_resume(current, 0))
			warning("failed to resume process:%lu (errno:%d %s)", (unsigned long)pid, errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}

	/* Update process name */
	if ((e = basename_alloc(data->abspath, &comm))) {
		warning("failed to update name of process:%lu [%s name:\"%s\" cwd:\"%s\"] (errno:%d %s)",
				(unsigned long)pid, pink_bitness_name(bit),
				data->comm, data->cwd,
				-e, strerror(-e));
		comm = xstrdup("???");
	} else if (strcmp(comm, data->comm)) {
		info("updating name of process:%lu [%s name:\"%s\" cwd:\"%s\"] to \"%s\" due to execve()",
				(unsigned long)pid, pink_bitness_name(bit),
				data->comm, data->cwd, comm);
	}

	if (data->comm)
		free(data->comm);
	data->comm = comm;

	free(data->abspath);
	data->abspath = NULL;

	return r;
}

static int callback_syscall(PINK_GCC_ATTR((unused)) const pink_easy_context_t *ctx,
		pink_easy_process_t *current, bool entering)
{
	return entering ? sysenter(current) : sysexit(current);
}

void callback_init(void)
{
	memset(&pandora->callback_table, 0, sizeof(pink_easy_callback_table_t));

	pandora->callback_table.startup = callback_startup;
	pandora->callback_table.cleanup = callback_cleanup;
	pandora->callback_table.exit = callback_exit;
	pandora->callback_table.exec = callback_exec;
	pandora->callback_table.syscall = callback_syscall;
	pandora->callback_table.error = callback_error;
	pandora->callback_table.cerror = callback_child_error;
}
