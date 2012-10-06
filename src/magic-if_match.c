/*
 * sydbox/magic-if_match.c
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <stdlib.h>
#include <sys/queue.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "slist.h"

static int magic_edit_if_match(const void *val, slist_t *if_match, bool append)
{
	const char *str = val;
	struct snode *node;

	if (!str || !*str)
		return MAGIC_RET_INVALID_VALUE;

	if (append) {
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(if_match, node, up);
	} else {
		SLIST_FOREACH(node, if_match, up) {
			if (streq(node->data, str)) {
				SLIST_REMOVE(if_match, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
	}

	return MAGIC_RET_OK;
}

int magic_append_exec_kill_if_match(const void *val,
				    struct pink_easy_process *current)
{
	return magic_edit_if_match(val, &sydbox->config.exec_kill_if_match,
				   true);
}

int magic_remove_exec_kill_if_match(const void *val,
				    struct pink_easy_process *current)
{
	return magic_edit_if_match(val, &sydbox->config.exec_kill_if_match,
				   false);
}

int magic_append_exec_resume_if_match(const void *val,
				      struct pink_easy_process *current)
{
	return magic_edit_if_match(val, &sydbox->config.exec_resume_if_match,
				   true);
}

int magic_remove_exec_resume_if_match(const void *val,
				      struct pink_easy_process *current)
{
	return magic_edit_if_match(val, &sydbox->config.exec_resume_if_match,
				   false);
}
