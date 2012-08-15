/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
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

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "log.h"

int magic_set_trace_follow_fork(const void *val, struct pink_easy_process *current)
{
	sydbox->config.follow_fork = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_trace_follow_fork(struct pink_easy_process *current)
{
	return sydbox->config.follow_fork;
}

int magic_set_trace_exit_wait_all(const void *val, struct pink_easy_process *current)
{
	sydbox->config.exit_wait_all = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_trace_exit_wait_all(struct pink_easy_process *current)
{
	return sydbox->config.exit_wait_all;
}

int magic_set_trace_use_seccomp(const void *val, struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	sydbox->config.use_seccomp = PTR_TO_BOOL(val);
#else
	log_magic("seccomp support not enabled, ignoring magic");
#endif
	return 0;
}

int magic_query_trace_use_seccomp(struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	return sydbox->config.use_seccomp;
#else
	return MAGIC_ERROR_NOT_SUPPORTED;
#endif
}

int magic_set_trace_magic_lock(const void *val, struct pink_easy_process *current)
{
	int l;
	const char *str = val;
	sandbox_t *box = box_current(current);

	if ((l = lock_state_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	box->magic_lock = (enum lock_state)l;
	return 0;
}

int magic_set_trace_interrupt(const void *val, struct pink_easy_process *current)
{
	int intr;
	const char *str = val;

	if ((intr = trace_interrupt_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.trace_interrupt = (enum pink_easy_intr)intr;
	return 0;
}
