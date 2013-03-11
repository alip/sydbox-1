/*
 * sydbox/sockmap.h
 *
 * save/query socket information
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SOCKMAP_H
#define SOCKMAP_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xfunc.h"
#include "sockmatch.h"
#include "sydhash.h"

struct sockmap {
	int fd;
	struct sockinfo *info;
	UT_hash_handle hh;
};

static inline void sockmap_add(struct sockmap *map, int fd, struct sockinfo *info)
{
	struct sockmap *s = xmalloc(sizeof(struct sockmap));
	s->fd = fd;
	s->info = info;
	HASH_ADD_INT(map, fd, s);
}

static inline const struct sockinfo *sockmap_find(struct sockmap *map, int fd)
{
	struct sockmap *s;

	HASH_FIND_INT(map, &fd, s);
	return s ? s->info : NULL;
}

static inline void sockmap_remove(struct sockmap *map, int fd)
{
	struct sockmap *s;

	HASH_FIND_INT(map, &fd, s);
	HASH_DEL(map, s);
	free_sockinfo(s->info);
	free(s);
}

static inline void sockmap_destroy(struct sockmap *map)
{
	struct sockmap *e, *t;

	HASH_ITER(hh, map, e, t) {
		if (e->info)
			free_sockinfo(e->info);
	}
	HASH_CLEAR(hh, map);
}

#endif
