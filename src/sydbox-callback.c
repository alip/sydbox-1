/*
 * sydbox/sydbox-callback.c
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
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
#include "log.h"
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
		log_fatal("%s (errno:%d %s)",
			  pink_easy_strerror(error),
			  errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_ALLOC:
	case PINK_EASY_ERROR_FORK:
		errctx = va_arg(ap, const char *);
		log_fatal("%s: %s (errno:%d %s)",
			  pink_easy_strerror(error),
			  errctx, errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_ATTACH:
		tid = va_arg(ap, pid_t);
		log_fatal("%s (process:%lu errno:%d %s)",
			  pink_easy_strerror(error),
			  (unsigned long)tid,
			  errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_TRACE:
	case PINK_EASY_ERROR_PROCESS:
		current = va_arg(ap, struct pink_easy_process *);
		errctx = va_arg(ap, const char *);
		if (error == PINK_EASY_ERROR_TRACE) { /* errno is set! */
			log_fatal("%s (ctx:%s process:%lu [abi:%d] errno:%d %s)",
				  pink_easy_strerror(error), errctx,
				  (unsigned long)pink_easy_process_get_tid(current),
				  pink_easy_process_get_abi(current),
				  errno, strerror(errno));
		} else { /* if (error == PINK_EASY_ERROR_PROCESS */
			log_fatal("%s (process:%lu [abi:%d])",
				  pink_easy_strerror(error),
				  (unsigned long)pink_easy_process_get_tid(current),
				  pink_easy_process_get_abi(current));
		}
		break;
	default:
		log_fatal("unknown error:%u", error);
		break;
	}

	va_end(ap);

	die("pinktrace error:%u", error);
}

static int callback_interrupt(const struct pink_easy_context *ctx, int fatal_sig)
{
	if (!fatal_sig)
		fatal_sig = SIGTERM;

	abort_all(fatal_sig);
	return 128 + fatal_sig;
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
	data = xcalloc(1, sizeof(proc_data_t));

	if (parent) {
		pdata = (proc_data_t *)pink_easy_process_get_userdata(parent);
		comm = xstrdup(pdata->comm);
		cwd = xstrdup(pdata->cwd);
		inherit = &pdata->config;
	} else {
		cwd = xgetcwd();
		comm = xstrdup(sydbox->program_invocation_name);
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

	SLIST_COPY_ALL(node, &inherit->whitelist_exec, up,
		       &data->config.whitelist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_read, up,
		       &data->config.whitelist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_write, up,
		       &data->config.whitelist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_network_bind, up,
		       &data->config.whitelist_network_bind, newnode,
		       sockmatch_xdup);
	SLIST_COPY_ALL(node, &inherit->whitelist_network_connect, up,
		       &data->config.whitelist_network_connect, newnode,
		       sockmatch_xdup);

	SLIST_COPY_ALL(node, &inherit->blacklist_exec, up,
		       &data->config.blacklist_exec, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_read, up,
		       &data->config.blacklist_read, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_write, up,
		       &data->config.blacklist_write, newnode, xstrdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_bind, up,
		       &data->config.blacklist_network_bind, newnode,
		       sockmatch_xdup);
	SLIST_COPY_ALL(node, &inherit->blacklist_network_connect, up,
		       &data->config.blacklist_network_connect, newnode,
		       sockmatch_xdup);
#undef SLIST_COPY_ALL

	/* Create the fd -> address hash table */
	data->sockmap = hashtable_create(NR_OPEN, 1);
	if (data->sockmap == NULL)
		die_errno("hashtable_create");

	pink_easy_process_set_userdata(current, data, free_proc);

	if (sydbox->config.whitelist_per_process_directories) {
		char *magic;
		xasprintf(&magic, "+/proc/%lu/***", (unsigned long)tid);
		magic_set_whitelist_read(magic, current);
		magic_set_whitelist_write(magic, current);
		free(magic);
	}

	log_trace("%s process %s[%lu:%u cwd=`%s']",
			parent ? "new" : "eldest", comm,
			(unsigned long)tid, abi, cwd);
	if (parent)
		log_trace("process:%lu has parent:%lu",
				(unsigned long)tid,
				(unsigned long)pink_easy_process_get_tid(parent));
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

	log_info("return value %d (%s access violations)",
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
			log_trace("eldest process:%lu exited"
					" with code:%d (status:%#x)",
					(unsigned long)tid, sydbox->exit_code,
					(unsigned)status);
		} else if (WIFSIGNALED(status)) {
			sydbox->exit_code = 128 + WTERMSIG(status);
			log_trace("eldest process:%lu was terminated"
					" with signal:%d (status:%#x)",
					(unsigned long)tid, sydbox->exit_code - 128,
					(unsigned)status);
		} else {
			sydbox->exit_code = EXIT_FAILURE;
			log_warning("eldest process:%lu exited"
					" with unknown status:%#x",
					(unsigned long)tid, (unsigned)status);
		}

		if (!sydbox->config.exit_wait_all) {
			cont_all();
			log_trace("loop abort due to eldest process %lu exit (status:%#x)",
					(unsigned long)tid, (unsigned)status);
			exit(sydbox->exit_code);
		}
	} else {
		if (WIFEXITED(status))
			log_trace("process:%lu exited"
					" with code:%d (status:%#x)",
					(unsigned long)tid,
					WEXITSTATUS(status),
					(unsigned)status);
		else if (WIFSIGNALED(status))
			log_trace("process:%lu was terminated"
					" with signal:%d (status:%#x)",
					(unsigned long)tid,
					WTERMSIG(status),
					(unsigned)status);
		else
			log_warning("process:%lu exited"
					" with unknown status:%#x",
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

	if (sydbox->wait_execve) {
		log_info("process %s[%lu:%u] entered execve() trap",
				sydbox->program_invocation_name,
				(unsigned long)tid, abi);
		sydbox->wait_execve = false;
		log_info("wait_execve cleared, sandboxing started");
		return 0;
	}

	if (data->config.magic_lock == LOCK_PENDING) {
		log_magic("lock magic commands for %s[%lu:%u]", data->comm,
				(unsigned long)tid, abi);
		data->config.magic_lock = LOCK_SET;
	}

	if (!data->abspath) {
		/* Nothing left to do */
		return 0;
	}

	/* kill_if_match and resume_if_match */
	r = 0;
	if (box_match_path(data->abspath, &sydbox->config.exec_kill_if_match, &match)) {
		log_warning("kill_if_match pattern=`%s'"
				" matches execve path=`%s'",
				match, data->abspath);
		log_warning("killing process:%lu"
				" [abi:%d cwd:`%s']",
				(unsigned long)tid, abi,
				data->cwd);
		if (pink_easy_process_kill(current, SIGKILL) < 0)
			log_warning("kill process:%lu failed"
					" (errno:%d %s)",
					(unsigned long)tid,
					errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}
	else if (box_match_path(data->abspath, &sydbox->config.exec_resume_if_match, &match)) {
		log_warning("resume_if_match pattern=`%s'"
				" matches execve path=`%s'",
				match, data->abspath);
		log_warning("resuming process:%lu"
				" [abi:%d cwd:\"%s\"]",
				(unsigned long)tid, abi, data->cwd);
		if (!pink_easy_process_resume(current, 0))
			log_warning("resume process:%lu failed"
					" (errno:%d %s)",
					(unsigned long)tid,
					errno, strerror(errno));
		r |= PINK_EASY_CFLAG_DROP;
	}

	/* Update process name */
	if ((e = basename_alloc(data->abspath, &comm))) {
		log_warning("update name of process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"] failed"
				" (errno:%d %s)",
				(unsigned long)tid, abi,
				data->comm, data->cwd,
				-e, strerror(-e));
		comm = xstrdup("???");
	} else if (strcmp(comm, data->comm)) {
		log_info("update name of process:%lu"
				" [abi=%d name=`%s' cwd:`%s']"
				" to `%s' due to execve()",
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
	int r;
	proc_data_t *data;

	if (sydbox->wait_execve) {
		log_info("waiting for execve()");
		return 0;
	}

	data = pink_easy_process_get_userdata(current);
	memcpy(&data->regs, regs, sizeof(pink_regs_t));

	if (entering) {
		r = sysenter(current);
	} else {
		r = sysexit(current);
		if (sydbox->config.use_seccomp)
			pink_easy_process_set_step(current, PINK_EASY_STEP_RESUME);
	}

	return r;
}

#if WANT_SECCOMP
static int callback_seccomp(const struct pink_easy_context *ctx,
		struct pink_easy_process *current, long ret_data)
{
	short flags;

	if (sydbox->wait_execve) {
		log_info("waiting for execve(), ret_data:%ld", ret_data);
		return 0;
	}

	/* Stop at syscall entry */
	pink_easy_process_set_step(current, PINK_EASY_STEP_SYSCALL);

	/* Let pinktrace recognize this is syscall entry */
	flags = pink_easy_process_get_flags(current);
	flags &= ~PINK_EASY_PROCESS_INSYSCALL;
	pink_easy_process_set_flags(current, flags);

	return 0;
}
#endif

void callback_init(void)
{
	memset(&sydbox->callback_table, 0, sizeof(struct pink_easy_callback_table));

	sydbox->callback_table.interrupt = callback_interrupt;
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
