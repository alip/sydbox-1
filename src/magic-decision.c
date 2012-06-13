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

int magic_set_abort_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = abort_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.abort_decision = (enum abort_decision)d;
	return 0;
}

int magic_set_panic_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = panic_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.panic_decision = (enum panic_decision)d;
	return 0;
}

int magic_set_violation_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = violation_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.violation_decision = (enum violation_decision)d;
	return 0;
}
