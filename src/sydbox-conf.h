/*
 * sydbox/sydbox-conf.h
 *
 * Compile-time configurable constants
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SYDBOX_CONF_H
#define SYDBOX_CONF_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>

/* Definitions */
#ifndef SYDBOX_PATH_MAX
#if defined(PATH_MAX)
#define SYDBOX_PATH_MAX (PATH_MAX+1)
#elif defined(MAXPATHLEN)
#define SYDBOX_PATH_MAX (MAXPATHLEN+1)
#else
#define SYDBOX_PATH_MAX (256+1)
#endif
#endif

#ifndef SYDBOX_PROFILE_CHAR
#define SYDBOX_PROFILE_CHAR '@'
#endif /* !SYDBOX_PROFILE_CHAR */

#ifndef SYDBOX_CONFIG_ENV
#define SYDBOX_CONFIG_ENV "SYDBOX_CONFIG"
#endif /* !SYDBOX_CONFIG_ENV */

#ifndef SYDBOX_JSON_DEBUG_ENV
#define SYDBOX_JSON_DEBUG_ENV "SYDBOX_JSON_DEBUG"
#endif /* !SYDBOX_JSON_DEBUG_ENV */

#ifndef SYDBOX_MAGIC_PREFIX
#define SYDBOX_MAGIC_PREFIX "/dev/sydbox"
#endif /* !SYDBOX_MAGIC_PREFIX */

#ifndef SYDBOX_MAGIC_SET_CHAR
#define SYDBOX_MAGIC_SET_CHAR ':'
#endif /* !SYDBOX_MAGIC_SET_CHAR */

#ifndef SYDBOX_MAGIC_QUERY_CHAR
#define SYDBOX_MAGIC_QUERY_CHAR '?'
#endif /* !SYDBOX_MAGIC_QUERY_CHAR */

#ifndef SYDBOX_MAGIC_APPEND_CHAR
#define SYDBOX_MAGIC_APPEND_CHAR '+'
#endif /* !SYDBOX_MAGIC_APPEND_CHAR */

#ifndef SYDBOX_MAGIC_REMOVE_CHAR
#define SYDBOX_MAGIC_REMOVE_CHAR '-'
#endif /* !SYDBOX_MAGIC_REMOVE_CHAR */

#ifndef SYDBOX_MAGIC_EXEC_CHAR
#define SYDBOX_MAGIC_EXEC_CHAR '!'
#endif /* !SYDBOX_MAGIC_EXEC_CHAR */

#endif
