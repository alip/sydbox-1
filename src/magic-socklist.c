/*
 * sydbox/magic-socklist.c
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "log.h"

static int magic_set_socklist(const void *val, slist_t *head)
{
	char op;
	int c, f, r = 0;
	const char *str = val;
	char **list;
	struct snode *node;
	struct sockmatch *match;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	/* Expand alias */
	c = f = sockmatch_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case SYDBOX_MAGIC_ADD_CHAR:
			errno = 0;
			if ((r = sockmatch_parse(list[c], &match)) < 0) {
				log_warning("invalid address `%s' (errno:%d %s)",
						list[c], -r, strerror(-r));
				r = MAGIC_ERROR_INVALID_VALUE;
				goto end;
			}
			if (errno == EAFNOSUPPORT) {
				/* ipv6 support disabled? */
				log_magic("ignore unsupported address=`%s'", list[c]);
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(head, node, up);
			break;
		case SYDBOX_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, head, up) {
				match = node->data;
				if (match->str && streq(match->str, str)) {
					SLIST_REMOVE(head, node, snode, up);
					free_sockmatch(match);
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

int magic_set_whitelist_network_bind(const void *val, struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->whitelist_network_bind);
}

int magic_set_whitelist_network_connect(const void *val, struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->whitelist_network_connect);
}

int magic_set_blacklist_network_bind(const void *val, struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->blacklist_network_bind);
}

int magic_set_blacklist_network_connect(const void *val, struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_socklist(val, &box->blacklist_network_connect);
}

int magic_set_filter_network(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	return magic_set_socklist(val, &sydbox->config.filter_network);
}
