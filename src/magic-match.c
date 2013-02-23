/*
 * sydbox/magic-match.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>

#include "macro.h"
#include "pathmatch.h"

int magic_set_match_case_sensitive(const void *val, syd_proc_t *current)
{
	pathmatch_set_case(PTR_TO_BOOL(val));
	return 0;
}

int magic_query_match_case_sensitive(syd_proc_t *current)
{
	return MAGIC_BOOL(pathmatch_get_case());
}

int magic_set_match_no_wildcard(const void *val, syd_proc_t *current)
{
	int no_wild;
	const char *str = val;

	no_wild = no_wildcard_from_string(str);
	if (no_wild < 0)
		return MAGIC_RET_INVALID_VALUE;

	pathmatch_set_no_wildcard(no_wild);
	return MAGIC_RET_OK;
}
