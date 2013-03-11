/*
 * sydbox/systable.c
 *
 * Copyright (c) 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"
#include <errno.h>
#include <stdlib.h>
#include <pinktrace/pink.h>
#include "log.h"
#include "sydhash.h"

struct systable {
	long no;
	sysentry_t entry;
	UT_hash_handle hh;
};

static struct systable *systable[PINK_ABIS_SUPPORTED];

void systable_add_full(long no, short abi, const char *name,
		       sysfunc_t fenter, sysfunc_t fexit)
{
	struct systable *s;

	s = xmalloc(sizeof(struct systable));
	s->no = no;
	s->entry.name = name;
	s->entry.enter = fenter;
	s->entry.exit = fexit;

	HASH_ADD_INT(systable[abi], no, s);
}

void systable_init(void)
{
	;
}

void systable_free(void)
{
	for (short abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		struct systable *s, *tmp;
		HASH_ITER(hh, systable[abi], s, tmp) {
			free(s);
		}
		HASH_CLEAR(hh, systable[abi]);
	}
}

void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit)
{
	long no;

	for (short abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		no = pink_lookup_syscall(name, abi);
		if (no != -1)
			systable_add_full(no, abi, name, fenter, fexit);
	}
}

const sysentry_t *systable_lookup(long no, short abi)
{
	struct systable *s;

	HASH_FIND_INT(systable[abi], &no, s);
	return s ? &(s->entry) : NULL;
}
