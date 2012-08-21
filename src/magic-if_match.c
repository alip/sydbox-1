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

static int magic_set_global_if_match(const void *val, slist_t *if_match)
{
	char op;
	const char *str = val;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	switch (op) {
	case SYDBOX_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(if_match, node, up);
		return 0;
	case SYDBOX_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, if_match, up) {
			if (streq(node->data, str)) {
				SLIST_REMOVE(if_match, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

int magic_set_exec_kill_if_match(const void *val, struct pink_easy_process *current)
{
	return magic_set_global_if_match(val, &sydbox->config.exec_kill_if_match);
}

int magic_set_exec_resume_if_match(const void *val, struct pink_easy_process *current)
{
	return magic_set_global_if_match(val, &sydbox->config.exec_resume_if_match);
}
