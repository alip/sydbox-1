/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
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

#ifndef SYDBOX_MAGIC_SEP_CHAR
#define SYDBOX_MAGIC_SEP_CHAR ':'
#endif /* !SYDBOX_MAGIC_SEP_CHAR */

#ifndef SYDBOX_MAGIC_QUERY_CHAR
#define SYDBOX_MAGIC_QUERY_CHAR '?'
#endif /* !SYDBOX_MAGIC_QUERY_CHAR */

#ifndef SYDBOX_MAGIC_ADD_CHAR
#define SYDBOX_MAGIC_ADD_CHAR '+'
#endif /* !SYDBOX_MAGIC_ADD_CHAR */

#ifndef SYDBOX_MAGIC_REMOVE_CHAR
#define SYDBOX_MAGIC_REMOVE_CHAR '-'
#endif /* !SYDBOX_MAGIC_REMOVE_CHAR */

#endif
