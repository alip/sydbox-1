/*
 * sydbox/magic-strlist.c
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "pathmatch.h"

static int magic_set_strlist(const void *val, slist_t *head)
{
	int c, f, r = 0;
	char op;
	const char *str = val;
	char **list;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	/* Expand pattern */
	c = f = pathmatch_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case SYDBOX_MAGIC_ADD_CHAR:
			node = xcalloc(1, sizeof(struct snode));
			node->data = xstrdup(list[c]);
			SLIST_INSERT_HEAD(head, node, up);
			break;
		case SYDBOX_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, head, up) {
				if (streq(node->data, list[c])) {
					SLIST_REMOVE(head, node, snode, up);
					free(node->data);
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

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

int magic_set_whitelist_exec(const void *val,
			     struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->whitelist_exec);
}

int magic_set_whitelist_read(const void *val,
			     struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->whitelist_read);
}

int magic_set_whitelist_write(const void *val,
			      struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->whitelist_write);
}

int magic_set_blacklist_exec(const void *val,
			     struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->blacklist_exec);
}

int magic_set_blacklist_read(const void *val,
			     struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->blacklist_read);
}

int magic_set_blacklist_write(const void *val,
			      struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_set_strlist(val, &box->blacklist_write);
}

int magic_set_filter_exec(const void *val,
			  struct pink_easy_process *current)
{
	return magic_set_strlist(val, &sydbox->config.filter_exec);
}

int magic_set_filter_read(const void *val,
			  struct pink_easy_process *current)
{
	return magic_set_strlist(val, &sydbox->config.filter_read);
}

int magic_set_filter_write(const void *val,
			   struct pink_easy_process *current)
{
	return magic_set_strlist(val, &sydbox->config.filter_write);
}
