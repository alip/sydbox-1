/*
 * sydbox/pathmatch.h
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef PATHMATCH_H
#define PATHMATCH_H 1

#include "strtable.h"

#define WILD3_SUFFIX "/***"

enum no_wildcard {
	NO_WILDCARD_LITERAL,
	NO_WILDCARD_PREFIX,
};
static const char *const no_wildcard_table[] = {
	[NO_WILDCARD_LITERAL] = "literal",
	[NO_WILDCARD_PREFIX] = "prefix"
};
DEFINE_STRING_TABLE_LOOKUP(no_wildcard, int)

extern void pathmatch_set_case(bool case_sensitive);
extern bool pathmatch_get_case(void);

extern void pathmatch_set_no_wildcard(enum no_wildcard no_wild);
extern enum no_wildcard patchmatch_get_no_wildcard(void);

extern int pathmatch_expand(const char *pattern, char ***buf);
extern int pathmatch(const char *pattern, const char *text);

#endif
