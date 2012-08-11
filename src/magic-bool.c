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

int magic_set_violation_raise_fail(const void *val, struct pink_easy_process *current)
{
	sydbox->config.violation_raise_fail = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_violation_raise_fail(struct pink_easy_process *current)
{
	return sydbox->config.violation_raise_fail;
}

int magic_set_violation_raise_safe(const void *val, struct pink_easy_process *current)
{
	sydbox->config.violation_raise_safe = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_violation_raise_safe(struct pink_easy_process *current)
{
	return sydbox->config.violation_raise_safe;
}

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
	return 0;
#else
	return MAGIC_ERROR_NOT_SUPPORTED;
#endif
}

int magic_query_trace_use_seccomp(struct pink_easy_process *current)
{
#ifdef WANT_SECCOMP
	return sydbox->config.use_seccomp;
#else
	return MAGIC_ERROR_NOT_SUPPORTED;
#endif
}

int magic_set_whitelist_ppd(const void *val, struct pink_easy_process *current)
{
	sydbox->config.whitelist_per_process_directories = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_ppd(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_per_process_directories;
}

int magic_set_whitelist_sb(const void *val, struct pink_easy_process *current)
{
	sydbox->config.whitelist_successful_bind = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_sb(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_successful_bind;
}

int magic_set_whitelist_usf(const void *val, struct pink_easy_process *current)
{
	sydbox->config.whitelist_unsupported_socket_families = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_usf(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_unsupported_socket_families;
}
