/*
 * sydbox/magic-whitelist.c
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

int magic_set_whitelist_ppd(const void *val,
			    struct pink_easy_process *current)
{
	sydbox->config.whitelist_per_process_directories = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_ppd(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_per_process_directories;
}

int magic_set_whitelist_sb(const void *val,
			   struct pink_easy_process *current)
{
	sydbox->config.whitelist_successful_bind = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_sb(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_successful_bind;
}

int magic_set_whitelist_usf(const void *val,
			    struct pink_easy_process *current)
{
	sydbox->config.whitelist_unsupported_socket_families = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_whitelist_usf(struct pink_easy_process *current)
{
	return sydbox->config.whitelist_unsupported_socket_families;
}
