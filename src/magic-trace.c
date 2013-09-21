/*
 * sydbox/magic-trace.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>

#include "macro.h"
#include "log.h"

int magic_set_trace_follow_fork(const void *val, syd_proc_t *current)
{
	sydbox->config.follow_fork = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_follow_fork(syd_proc_t *current)
{
	return MAGIC_BOOL(sydbox->config.follow_fork);
}

int magic_set_trace_exit_kill(const void *val, syd_proc_t *current)
{
#if PINK_HAVE_OPTION_EXITKILL
	sydbox->config.exit_kill = PTR_TO_BOOL(val);
#else
	log_magic("PTRACE_O_EXITKILL not supported, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_exit_kill(syd_proc_t *current)
{
	return MAGIC_BOOL(sydbox->config.exit_kill);
}

int magic_set_trace_exit_wait_all(const void *val, syd_proc_t *current)
{
#if SYDBOX_HAVE_SECCOMP
	log_magic("seccomp support enabled, force exit_wait_all to true");
	sydbox->config.exit_wait_all = true;
#else
	sydbox->config.exit_wait_all = PTR_TO_BOOL(val);
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_exit_wait_all(syd_proc_t *current)
{
	return MAGIC_BOOL(sydbox->config.exit_wait_all);
}

int magic_set_trace_use_seccomp(const void *val, syd_proc_t *current)
{
#if SYDBOX_HAVE_SECCOMP
	sydbox->config.use_seccomp = PTR_TO_BOOL(val);
#else
	log_magic("seccomp support not enabled, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_use_seccomp(syd_proc_t *current)
{
#if SYDBOX_HAVE_SECCOMP
	return sydbox->config.use_seccomp;
#else
	return MAGIC_RET_NOT_SUPPORTED;
#endif
}

int magic_set_trace_use_seize(const void *val, syd_proc_t *current)
{
#if PINK_HAVE_SEIZE && PINK_HAVE_INTERRUPT && PINK_HAVE_LISTEN
	sydbox->config.use_seize = PTR_TO_BOOL(val);
#else
	log_magic("PTRACE_SEIZE not supported, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_use_seize(syd_proc_t *current)
{
#if PINK_HAVE_SEIZE && PINK_HAVE_INTERRUPT && PINK_HAVE_LISTEN
	return sydbox->config.use_seize;
#else
	return MAGIC_RET_NOT_SUPPORTED;
#endif
}

int magic_set_trace_use_toolong_hack(const void *val, syd_proc_t *current)
{
	sydbox->config.use_toolong_hack = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_use_toolong_hack(syd_proc_t *current)
{
	return sydbox->config.use_toolong_hack;
}

int magic_set_trace_magic_lock(const void *val, syd_proc_t *current)
{
	int l;
	const char *str = val;
	sandbox_t *box = box_current(current);

	l = lock_state_from_string(str);
	if (l < 0)
		return MAGIC_RET_INVALID_VALUE;

	box->magic_lock = (enum lock_state)l;
	return MAGIC_RET_OK;
}

int magic_set_trace_interrupt(const void *val, syd_proc_t *current)
{
	int intr;
	const char *str = val;

	intr = trace_interrupt_from_string(str);
	if (intr < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.trace_interrupt = (enum trace_interrupt)intr;
	return MAGIC_RET_OK;
}
