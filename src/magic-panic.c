/*
 * sydbox/magic-panic.c
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

int magic_set_abort_decision(const void *val,
			     struct pink_easy_process *current)
{
	int d;
	const char *str = val;

	d = abort_decision_from_string(str);
	if (d < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.abort_decision = (enum abort_decision)d;
	return 0;
}

int magic_set_panic_decision(const void *val,
			     struct pink_easy_process *current)
{
	int d;
	const char *str = val;

	d = panic_decision_from_string(str);
	if (d < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.panic_decision = (enum panic_decision)d;
	return 0;
}

int magic_set_panic_exit_code(const void *val,
			      struct pink_easy_process *current)
{
	sydbox->config.panic_exit_code = PTR_TO_INT(val);
	return 0;
}

int magic_set_violation_decision(const void *val,
				 struct pink_easy_process *current)
{
	int d;
	const char *str = val;

	d = violation_decision_from_string(str);
	if (d < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.violation_decision = (enum violation_decision)d;
	return 0;
}

int magic_set_violation_exit_code(const void *val,
				  struct pink_easy_process *current)
{
	sydbox->config.violation_exit_code = PTR_TO_INT(val);
	return 0;
}

int magic_set_violation_raise_fail(const void *val,
				   struct pink_easy_process *current)
{
	sydbox->config.violation_raise_fail = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_violation_raise_fail(struct pink_easy_process *current)
{
	return sydbox->config.violation_raise_fail;
}

int magic_set_violation_raise_safe(const void *val,
				   struct pink_easy_process *current)
{
	sydbox->config.violation_raise_safe = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_violation_raise_safe(struct pink_easy_process *current)
{
	return sydbox->config.violation_raise_safe;
}
