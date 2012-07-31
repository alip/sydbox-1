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

int magic_set_match_case_sensitive(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	sydbox->config.match_case_sensitive = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_match_case_sensitive(PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	return sydbox->config.match_case_sensitive;
}

int magic_set_match_no_wildcard(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	int nw;
	const char *str = val;

	if ((nw = no_wildcard_mode_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.match_no_wildcard = (enum no_wildcard_mode)nw;
	return 0;
}
