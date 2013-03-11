/*
 * sydbox/sydhash.h
 *
 * Configure uthash.h for sydbox
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SYDHASH_H
#define SYDHASH_H 1

#include "log.h"
#define uthash_fatal(msg)	die("uthash internal error: %s", (msg))
#define uthash_malloc		xmalloc
#include "uthash.h"

#endif
