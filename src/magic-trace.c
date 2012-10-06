/*
 * sydbox/magic-trace.c
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "log.h"

int magic_set_trace_follow_fork(const void *val,
				struct pink_easy_process *current)
{
	sydbox->config.follow_fork = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_trace_follow_fork(struct pink_easy_process *current)
{
	return MAGIC_BOOL(sydbox->config.follow_fork);
}

int magic_set_trace_exit_wait_all(const void *val,
				  struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	log_magic("seccomp support enabled, force exit_wait_all to true");
	sydbox->config.exit_wait_all = true;
#else
	sydbox->config.exit_wait_all = PTR_TO_BOOL(val);
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_exit_wait_all(struct pink_easy_process *current)
{
	return MAGIC_BOOL(sydbox->config.exit_wait_all);
}

int magic_set_trace_use_seccomp(const void *val,
				struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	sydbox->config.use_seccomp = PTR_TO_BOOL(val);
#else
	log_magic("seccomp support not enabled, ignoring magic");
#endif
	return MAGIC_RET_OK;
}

int magic_query_trace_use_seccomp(struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	return sydbox->config.use_seccomp;
#else
	return MAGIC_RET_NOT_SUPPORTED;
#endif
}

int magic_set_trace_magic_lock(const void *val,
			       struct pink_easy_process *current)
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

int magic_set_trace_interrupt(const void *val,
			      struct pink_easy_process *current)
{
	int intr;
	const char *str = val;

	intr = trace_interrupt_from_string(str);
	if (intr < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.trace_interrupt = (enum pink_easy_intr)intr;
	return MAGIC_RET_OK;
}
