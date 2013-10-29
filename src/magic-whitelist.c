/*
 * sydbox/magic-whitelist.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include <pinktrace/pink.h>

#include "macro.h"

int magic_set_whitelist_ppd(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_per_process_directories = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_ppd(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_per_process_directories);
}

int magic_set_whitelist_sb(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_successful_bind = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_sb(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_successful_bind);
}

int magic_set_whitelist_usf(const void *val, syd_process_t *current)
{
	sydbox->config.whitelist_unsupported_socket_families = PTR_TO_BOOL(val);
	return MAGIC_RET_OK;
}

int magic_query_whitelist_usf(syd_process_t *current)
{
	return MAGIC_BOOL(sydbox->config.whitelist_unsupported_socket_families);
}
