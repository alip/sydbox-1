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

static int callback_child_error(enum pink_easy_child_error error)
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
	pid_t tid;
	enum pink_easy_error error;
	struct pink_easy_process *current;

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
		tid = va_arg(ap, pid_t);
		fatal("error: %s (process:%lu errno:%d %s)\n",
				pink_easy_strerror(error),
				(unsigned long)tid,
				errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_TRACE:
	case PINK_EASY_ERROR_PROCESS:
		current = va_arg(ap, struct pink_easy_process *);
		errctx = va_arg(ap, const char *);
		if (error == PINK_EASY_ERROR_TRACE) { /* errno is set! */
			fatal("error: %s (ctx:%s process:%lu [abi:%d] errno:%d %s)",
					pink_easy_strerror(error), errctx,
					(unsigned long)pink_easy_process_get_tid(current),
					pink_easy_process_get_abi(current),
					errno, strerror(errno));
		} else { /* if (error == PINK_EASY_ERROR_PROCESS */
			fatal("error: %s (process:%lu [abi:%d])",
					pink_easy_strerror(error),
					(unsigned long)pink_easy_process_get_tid(current),
					pink_easy_process_get_abi(current));
		}
		break;
	default:
		fatal("error: unknown:%u\n", error);
		break;
	}

	va_end(ap);
}

static void callback_startup(const struct pink_easy_context *ctx,
		struct pink_easy_process *current,
		struct pink_easy_process *parent)
{
	int r;
	pid_t tid;
	enum pink_abi abi;
	short flags;
	bool attached;
	char *cwd, *comm;
	struct snode *node, *newnode;
	proc_data_t *data, *pdata;
	sandbox_t *inherit;

	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	flags = pink_easy_process_get_flags(current);
	attached = !!(flags & PINK_EASY_PROCESS_ATTACHED);
	data = xcalloc(1, sizeof(proc_data_t));

	if (parent) {
		pdata = (proc_data_t *)pink_easy_process_get_userdata(parent);
		comm = xstrdup(pdata->comm);
		cwd = xstrdup(pdata->cwd);
		inherit = &pdata->config;
	} else {
		if (attached) {
			/* Figure out process name */
			if ((r = proc_comm(tid, &comm))) {
				warning("failed to read the name of"
						" process:%lu [abi:%d] (errno:%d %s)",
						(unsigned long)tid, abi,
						-r, strerror(-r));
				comm = xstrdup("???");
			}

			/* Figure out the current working directory */
			if ((r = proc_cwd(tid, &cwd))) {
				warning("failed to get working directory of the initial "
						"process:%lu [abi:%d name:\"%s\"] (errno:%d %s)",
						(unsigned long)tid, abi, comm,
						-r, strerror(-r));
				free(data);
				panic(current);
				return;
			}
		} else {
			cwd = xgetcwd();
			comm = xstrdup(sydbox->program_invocation_name);
		}

		sydbox->eldest = tid;
		inherit = &sydbox->config.child;
	}

	/* Copy the configuration */
	data->config.sandbox_exec = inherit->sandbox_exec;
	data->config.sandbox_read = inherit->sandbox_read;
	data->config.sandbox_write = inherit->sandbox_write;
	data->config.sandbox_network = inherit->sandbox_network;
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
	SLIST_COPY_ALL(node, &inherit->whitelist_network_bind, up, &data->config.whitelist_network_bind, newnode, sock_match_xdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_network_connect, up, &data->config.whitelist_network_connect, newnode, sock_match_xdup);

	SLIST_COPY_ALL(node, &inherit->blacklist_exec, up, &data->config.blacklist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_read, up, &data->config.blacklist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_write, up, &data->config.blacklist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_bind, up, &data->config.blacklist_network_bind, newnode, sock_match_xdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_connect, up, &data->config.blacklist_network_connect, newnode, sock_match_xdup);
#undef SLIST_COPY_ALL

	/* Create the fd -> address hash table */
	if ((r = hashtable_create(NR_OPEN, 1, &data->sockmap)) < 0) {
		errno = -r;
		die_errno(-1, "hashtable_create");
	}

	pink_easy_process_set_userdata(current, data, free_proc);

	if (sydbox->config.whitelist_per_process_directories) {
		char *magic;
		xasprintf(&magic, "+/proc/%lu/***", (unsigned long)tid);
		magic_set_whitelist_read(magic, current);
		magic_set_whitelist_write(magic, current);
		free(magic);
	}

	info("startup: %s process:%lu [abi:%d name:\"%s\" cwd:\"%s\"]",
			(!parent && !attached) ? "initial" : "new",
			(unsigned long)tid, abi, comm, cwd);
	if (parent)
		info("startup: process:%lu has parent:%lu", (unsigned long)tid,
				(unsigned long)pink_easy_process_get_tid(parent));
	else
		info("startup: process:%lu has no parent", (unsigned long)tid);
}

static int callback_cleanup(const struct pink_easy_context *ctx)
{
	int r = sydbox->exit_code;

	if (sydbox->violation) {
		if (sydbox->config.violation_exit_code > 0)
			r = sydbox->config.violation_exit_code;
		else if (sydbox->config.violation_exit_code == 0)
			r = 128 + sydbox->exit_code;
	}

	info("cleanup: return value %d (%s access violations)",
			r, sydbox->violation ? "due to" : "no");
	return r;
}

static int callback_exit(const struct pink_easy_context *ctx,
		pid_t tid, int status)
{
	if (tid == sydbox->eldest) {
		/* Eldest process, keep return code */
		if (WIFEXITED(status)) {
			sydbox->exit_code = WEXITSTATUS(status);
			info("initial process:%lu exited with code:%d (status:%#x)",
					(unsigned long)tid, sydbox->exit_code,
					(unsigned)status);
		} else if (WIFSIGNALED(status)) {
			sydbox->exit_code = 128 + WTERMSIG(status);
			info("initial process:%lu was terminated with signal:%d (status:%#x)",
					(unsigned long)tid, sydbox->exit_code - 128,
					(unsigned)status);
		} else {
			sydbox->exit_code = EXIT_FAILURE;
			warning("initial process:%lu exited with unknown status:%#x",
					(unsigned long)tid, (unsigned)status);
		}

		if (!sydbox->config.exit_wait_all) {
			cont_all();
			info("loop: aborted due to initial child exit");
			exit(sydbox->exit_code);
		}
	} else {
		if (WIFEXITED(status))
			info("process:%lu exited with code:%d (status:%#x)",
					(unsigned long)tid,
					WEXITSTATUS(status),
					(unsigned)status);
		else if (WIFSIGNALED(status))
			info("process:%lu exited was terminated with signal:%d (status:%#x)",
					(unsigned long)tid,
					WTERMSIG(status),
					(unsigned)status);
		else
			warning("process:%lu exited with unknown status:%#x",
					(unsigned long)tid, (unsigned)status);
	}

	return 0;
}

static int callback_exec(const struct pink_easy_context *ctx,
		struct pink_easy_process *current,
		const pink_regs_t *regs,
		enum pink_abi orig_abi)
{
	int e, r;
	char *comm;
	const char *match;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sydbox->wait_execve > 0) {
		info("exec: skipped successful execve()");
		sydbox->wait_execve--;
		return 0;
	}

	if (data->config.magic_lock == LOCK_PENDING) {
		info("locking magic commands for"
				" process:%lu [abi:%d name:\"%s\" cwd:\"%s\"]",
				(unsigned long)tid, abi,
				data->comm, data->cwd);
		data->config.magic_lock = LOCK_SET;
	}

	if (!data->abspath) {
		/* Nothing left to do */
		return 0;
	}

	/* kill_if_match and resume_if_match */
	r = 0;
	if (box_match_path(data->abspath, &sydbox->config.exec_kill_if_match, &match)) {
		warning("kill_if_match pattern `%s' matches execve path `%s'", match, data->abspath);
		warning("killing process:%lu [abi:%d cwd:\"%s\"]", (unsigned long)tid, abi, data->cwd);
		if (pink_easy_process_kill(current, SIGKILL) < 0)
			warning("failed to kill process:%lu (errno:%d %s)", (unsigned long)tid, errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}
	else if (box_match_path(data->abspath, &sydbox->config.exec_resume_if_match, &match)) {
		warning("resume_if_match pattern `%s' matches execve path `%s'", match, data->abspath);
		warning("resuming process:%lu [abi:%d cwd:\"%s\"]", (unsigned long)tid, abi, data->cwd);
		if (!pink_easy_process_resume(current, 0))
			warning("failed to resume process:%lu (errno:%d %s)",
					(unsigned long)tid, errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}

	/* Update process name */
	if ((e = basename_alloc(data->abspath, &comm))) {
		warning("failed to update name of process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"] (errno:%d %s)",
				(unsigned long)tid, abi,
				data->comm, data->cwd,
				-e, strerror(-e));
		comm = xstrdup("???");
	} else if (strcmp(comm, data->comm)) {
		info("updating name of process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"] to \"%s\" due to execve()",
				(unsigned long)tid, abi,
				data->comm, data->cwd, comm);
	}

	if (data->comm)
		free(data->comm);
	data->comm = comm;

	free(data->abspath);
	data->abspath = NULL;

	return r;
}

static int callback_syscall(const struct pink_easy_context *ctx,
		struct pink_easy_process *current,
		const pink_regs_t *regs,
		bool entering)
{
	if (sydbox->wait_execve > 0) {
		info("syscall: skipped successful execve() return");
		sydbox->wait_execve--;
		return 0;
	}

	proc_data_t *data = pink_easy_process_get_userdata(current);
	memcpy(&data->regs, regs, sizeof(pink_regs_t));

	if (sydbox->config.use_seccomp) {
		pink_easy_process_set_step(current, PINK_EASY_STEP_RESUME);
		return sysexit(current);
	}
	return entering ? sysenter(current) : sysexit(current);
}

#if WANT_SECCOMP
static int callback_seccomp(const struct pink_easy_context *ctx,
		struct pink_easy_process *current, long ret_data)
{
	int r;
	const sysentry_t *entry;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sydbox->wait_execve > 0) {
		info("seccomp: skipped execve() syscall trap");
		sydbox->wait_execve--;
		return 0;
	}

#if PINK_HAVE_REGS_T
	if (!pink_trace_get_regs(tid, &data->regs)) {
		warning("seccomp: trace_get_regs failed (errno:%d %s)", errno, strerror(errno));
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DROP : panic(current);
	}
#else
	data->regs = 0;
#endif

	r = sysenter(current);
	if (r == 0) {
		entry = systable_lookup(data->sno, abi);
		if (data->deny || entry->exit) /* must stop at exit */
			pink_easy_process_set_step(current, PINK_EASY_STEP_SYSCALL);
	}
	return r;
}
#endif

void callback_init(void)
{
	memset(&sydbox->callback_table, 0, sizeof(struct pink_easy_callback_table));

	sydbox->callback_table.startup = callback_startup;
	sydbox->callback_table.cleanup = callback_cleanup;
	sydbox->callback_table.exit = callback_exit;
	sydbox->callback_table.exec = callback_exec;
	sydbox->callback_table.syscall = callback_syscall;
#if WANT_SECCOMP
	if (sydbox->config.use_seccomp)
		sydbox->callback_table.seccomp = callback_seccomp;
#endif
	sydbox->callback_table.error = callback_error;
	sydbox->callback_table.cerror = callback_child_error;
}
