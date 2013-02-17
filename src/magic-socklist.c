/*
 * sydbox/magic-socklist.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pinktrace/pink.h>

#include "macro.h"
#include "log.h"

static int magic_edit_socklist(const void *val, slist_t *head, bool append)
{
	int c, f, r = MAGIC_RET_OK;
	const char *str = val;
	char **list;
	struct snode *node;
	struct sockmatch *match;

	if (!str || !*str)
		return MAGIC_RET_INVALID_VALUE;

	/* Expand alias */
	c = f = sockmatch_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		if (append) {
			errno = 0;
			if ((r = sockmatch_parse(list[c], &match)) < 0) {
				log_warning("invalid address `%s' (errno:%d %s)",
					    list[c], -r, strerror(-r));
				r = MAGIC_RET_INVALID_VALUE;
				goto end;
			}
			if (errno == EAFNOSUPPORT) {
				/* ipv6 support disabled? */
				log_magic("ignore unsupported address=`%s'",
					  list[c]);
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(head, node, up);
		} else {
			SLIST_FOREACH(node, head, up) {
				match = node->data;
				if (match->str && streq(match->str, str)) {
					SLIST_REMOVE(head, node, snode, up);
					free_sockmatch(match);
					free(node);
					break;
				}
			}
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

int magic_append_whitelist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->whitelist_network_bind, true);
}

int magic_remove_whitelist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->whitelist_network_bind, false);
}

int magic_append_whitelist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->whitelist_network_connect, true);
}

int magic_remove_whitelist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->whitelist_network_connect, false);
}

int magic_append_blacklist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->blacklist_network_bind, true);
}

int magic_remove_blacklist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->blacklist_network_bind, false);
}

int magic_append_blacklist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->blacklist_network_connect, true);
}

int magic_remove_blacklist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_socklist(val, &box->blacklist_network_connect, false);
}

int magic_append_filter_network(const void *val, syd_proc_t *current)
{
	return magic_edit_socklist(val, &sydbox->config.filter_network, true);
}

int magic_remove_filter_network(const void *val, syd_proc_t *current)
{
	return magic_edit_socklist(val, &sydbox->config.filter_network, false);
}
