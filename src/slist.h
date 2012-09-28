/*
 * sydbox/slist.h
 *
 * Generic singly-linked list based on sys/queue.h
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SLIST_H
#define SLIST_H 1

#include <stdlib.h>
#include <sys/queue.h>

#include "xfunc.h"

struct snode {
	void *data;
	SLIST_ENTRY(snode) up;
};
SLIST_HEAD(slist, snode);
typedef struct slist slist_t;

#define SLIST_COPY_ALL(var, head, field, newhead, newvar, copydata) \
	do { \
		SLIST_INIT(newhead); \
		SLIST_FOREACH(var, head, field) { \
			newvar = xcalloc(1, sizeof(struct snode)); \
			newvar->data = copydata(var->data); \
			SLIST_INSERT_HEAD(newhead, newvar, field); \
		} \
	} while (0)

#define SLIST_FREE_ALL(var, head, field, freedata) \
	do { \
		while ((var = SLIST_FIRST(head))) { \
			SLIST_REMOVE_HEAD(head, field); \
			freedata(var->data); \
			free(var); \
		} \
		SLIST_INIT(head); \
	} while (0)

#endif /* !SLIST_H */
