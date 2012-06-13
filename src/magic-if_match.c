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

int magic_set_exec_kill_if_match(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return magic_set_global_if_match(val, &sydbox->config.exec_kill_if_match);
}

int magic_set_exec_resume_if_match(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return magic_set_global_if_match(val, &sydbox->config.exec_resume_if_match);
}
