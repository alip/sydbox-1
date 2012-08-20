/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2012 Ali Polatel <alip@exherbo.org>
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

#include <errno.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"
#include "log.h"

static hashtable_t *systable[PINK_ABIS_SUPPORTED];

static void systable_add_full(long no, enum pink_abi abi, const char *name,
		sysfunc_t fenter, sysfunc_t fexit)
{
	sysentry_t *entry;

	entry = xmalloc(sizeof(sysentry_t));
	entry->name = name;
	entry->enter = fenter;
	entry->exit = fexit;

	ht_int32_node_t *node = hashtable_find(systable[abi], no, 1);
	node->data = entry;
}

void systable_init(void)
{
	int r;

	for (enum pink_abi abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		systable[abi] = hashtable_create(syscall_entries_max(), 0);
		if (systable[abi] == NULL)
			die_errno("hashtable_create");
	}
}

void systable_free(void)
{
	for (enum pink_abi abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		for (int i = 0; i < systable[abi]->size; i++) {
			ht_int32_node_t *node = HT_NODE(systable[abi], systable[abi]->nodes, i);
			if (node->data)
				free(node->data);
		}
		hashtable_destroy(systable[abi]);
	}
}

void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit)
{
	long no;

	for (enum pink_abi abi = 0; abi < PINK_ABIS_SUPPORTED; abi++) {
		no = pink_syscall_lookup(name, abi);
		if (no != -1)
			systable_add_full(no, abi, name, fenter, fexit);
	}
}

const sysentry_t *systable_lookup(long no, enum pink_abi abi)
{
	ht_int32_node_t *node = hashtable_find(systable[abi], no, 0);
	return node ? node->data : NULL;
}
