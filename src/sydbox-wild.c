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

#include "log.h"
#include "path.h"
#include "util.h"
#include "wildmatch.h"

#define WILD3_SUFFIX "/***"

int wildmatch_sydbox(const char *pattern, const char *text)
{
	int r;

	if (sydbox->config.match_case_sensitive)
		r = wildmatch(pattern, text);
	else
		r = iwildmatch(pattern, text);

	log_match("%smatch%s: pattern=`%s' text=`%s'",
			r == 0 ? "no" : "",
			sydbox->config.match_case_sensitive ? "" : "case",
			pattern, text);

	return r;
}

int wildmatch_expand(const char *pattern, char ***buf)
{
	int i, bufsiz;
	char *s, *p, *cp;
	char **list;

	assert(buf);

	p = xstrdup(pattern);
	if (sydbox->config.match_no_wildcard == NO_WILDCARD_PREFIX &&
			!strchr(p, '*') && !strchr(p, '?')) {
		cp = xmalloc(sizeof(char) * (strlen(p) + sizeof(WILD3_SUFFIX)));

		strcpy(cp, p);
		strcat(cp, WILD3_SUFFIX);

		free(p);
		p = cp;

		log_match("append `%s' to pattern=`%s' due to no_wildcard=prefix",
				WILD3_SUFFIX, p);
	}
	p = path_kill_slashes(p);

	if (endswith(p, WILD3_SUFFIX)) {
		list = xmalloc(sizeof(char *) * 2);
		s = xstrdup(p);
		i = strrchr(s, '/') - s;
		s[i] = '\0'; /* bare directory first */
		list[0] = xstrdup(s);
		s[i] = '/';
		s[i+3] = '\0'; /* two stars instead of three */
		list[1] = s;
		bufsiz = 2;
	} else {
		list = xmalloc(sizeof(char *));
		list[0] = xstrdup(p);
		bufsiz = 1;
	}

	free(p);
	*buf = list;
	return bufsiz;
}
