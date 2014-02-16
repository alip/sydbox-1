/*
 * sydbox/magic-panic.c
 *
 * Copyright (c) 2012, 2013, 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include "pink.h"

#include "macro.h"

int magic_set_abort_decision(const void *val, syd_process_t *current)
{
	int d;
	const char *str = val;

	d = abort_decision_from_string(str);
	if (d < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.abort_decision = (enum abort_decision)d;
	return MAGIC_RET_OK;
}

int magic_set_panic_decision(const void *val, syd_process_t *current)
{
	int d;
	const char *str = val;

	d = panic_decision_from_string(str);
	if (d < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.panic_decision = (enum panic_decision)d;
	return MAGIC_RET_OK;
}

int magic_set_panic_exit_code(const void *val, syd_process_t *current)
{
	sydbox->config.panic_exit_code = PTR_TO_INT(val);
	return MAGIC_RET_OK;
}

int magic_set_violation_decision(const void *val, syd_process_t *current)
{
	int d;
	const char *str = val;

	d = violation_decision_from_string(str);
	if (d < 0)
		return MAGIC_RET_INVALID_VALUE;

	sydbox->config.violation_decision = (enum violation_decision)d;
	return MAGIC_RET_OK;
}

int magic_set_violation_exit_code(const void *val, syd_process_t *current)
{
	sydbox->config.violation_exit_code = PTR_TO_INT(val);
	return MAGIC_RET_OK;
}

int magic_set_violation_raise_fail(const void *val, syd_process_t *current)
{
	sydbox->config.violation_raise_fail = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_violation_raise_fail(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.violation_raise_fail);
}

int magic_set_violation_raise_safe(const void *val, syd_process_t *current)
{
	sydbox->config.violation_raise_safe = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_violation_raise_safe(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.violation_raise_safe);
}
