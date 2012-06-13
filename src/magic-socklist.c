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
#include <errno.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"

static int magic_set_socklist(const void *val, slist_t *head)
{
	char op;
	int c, f, r = 0;
	const char *str = val;
	char **list;
	struct snode *node;
	sock_match_t *match;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case SYDBOX_MAGIC_ADD_CHAR:
			errno = 0;
			if ((r = sock_match_new(list[c], &match)) < 0) {
				warning("invalid address `%s' (errno:%d %s)",
						list[c], -r, strerror(-r));
				r = MAGIC_ERROR_INVALID_VALUE;
				goto end;
			}
			if (errno == EAFNOSUPPORT) {
				/* ipv6 support disabled? */
				info("unsupported address `%s' ignoring", list[c]);
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(head, node, up);
			break;
		case SYDBOX_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, head, up) {
				match = node->data;
				if (streq(match->str, str)) {
					SLIST_REMOVE(head, node, snode, up);
					free_sock_match(match);
					free(node);
					break;
				}
			}
			break;
		default:
			r = MAGIC_ERROR_INVALID_OPERATION;
			break;
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

int magic_set_whitelist_sock_bind(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->whitelist_sock_bind);
}

int magic_set_whitelist_sock_connect(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->whitelist_sock_connect);
}

int magic_set_blacklist_sock_bind(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->blacklist_sock_bind);
}

int magic_set_blacklist_sock_connect(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->blacklist_sock_connect);
}

int magic_set_filter_sock(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return magic_set_socklist(val, &sydbox->config.filter_sock);
}
