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

#include <assert.h>
#include <string.h>

#include "util.h"

#define WILD3_SUFFIX "/***"

int wildmatch_expand(const char *pattern, char ***buf)
{
	int i;
	char *s;
	char **list;

	assert(buf);

	if (endswith(pattern, WILD3_SUFFIX)) {
		list = xmalloc(sizeof(char *) * 2);
		s = xstrdup(pattern);
		i = strrchr(s, '/') - s;
		s[i] = '\0'; /* bare directory first */
		list[0] = xstrdup(s);
		s[i] = '/';
		s[i+3] = '\0'; /* two stars instead of three */
		list[1] = s;
		*buf = list;
		return 2;
	} else {
		list = xmalloc(sizeof(char *));
		list[0] = xstrdup(pattern);
		*buf = list;
		return 1;
	}
}
