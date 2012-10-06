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

static int magic_edit_strlist(const void *val, slist_t *head, bool append)
{
	int c, f, r = MAGIC_RET_OK;
	const char *str = val;
	char **list;
	struct snode *node;

	if (!str || !*str)
		return MAGIC_RET_INVALID_VALUE;

	/* Expand pattern */
	c = f = pathmatch_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		if (append) {
			node = xcalloc(1, sizeof(struct snode));
			node->data = xstrdup(list[c]);
			SLIST_INSERT_HEAD(head, node, up);
		} else {
			SLIST_FOREACH(node, head, up) {
				if (streq(node->data, list[c])) {
					SLIST_REMOVE(head, node, snode, up);
					free(node->data);
					free(node);
					break;
				}
			}
		}
	}

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

int magic_append_whitelist_exec(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_exec, true);
}

int magic_remove_whitelist_exec(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_exec, false);
}

int magic_append_whitelist_read(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_read, true);
}

int magic_remove_whitelist_read(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_read, false);
}

int magic_append_whitelist_write(const void *val,
				 struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_write, true);
}

int magic_remove_whitelist_write(const void *val,
				 struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->whitelist_write, false);
}

int magic_append_blacklist_exec(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_exec, true);
}

int magic_remove_blacklist_exec(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_exec, false);
}

int magic_append_blacklist_read(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_read, true);
}

int magic_remove_blacklist_read(const void *val,
				struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_read, false);
}

int magic_append_blacklist_write(const void *val,
				 struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_write, true);
}

int magic_remove_blacklist_write(const void *val,
				 struct pink_easy_process *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_strlist(val, &box->blacklist_write, false);
}

int magic_append_filter_exec(const void *val,
			     struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_exec, true);
}

int magic_remove_filter_exec(const void *val,
			     struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_exec, false);
}

int magic_append_filter_read(const void *val,
			     struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_read, true);
}

int magic_remove_filter_read(const void *val,
			     struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_read, false);
}

int magic_append_filter_write(const void *val,
			      struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_write, true);
}

int magic_remove_filter_write(const void *val,
			      struct pink_easy_process *current)
{
	return magic_edit_strlist(val, &sydbox->config.filter_write, false);
}
