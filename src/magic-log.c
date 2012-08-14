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

#include "sydbox-defs.h"

#include <stdlib.h>
#include <errno.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"
#include "macro.h"

int magic_set_log_file(const void *val, struct pink_easy_process *current)
{
	int r;
	const char *filename = val;

	if (!filename /* || !*filename */)
		return MAGIC_ERROR_INVALID_VALUE;

	log_close();

	if (*filename) {
		if ((r = log_init(filename)) < 0) {
			errno = -r;
			die_errno(3, "log_init for file `%s' failed", filename);
		}
	} else {
		log_init(NULL);
	}

	return 0;
}

int magic_set_log_level(const void *val, struct pink_easy_process *current)
{
	log_debug_level(PTR_TO_INT(val));
	return 0;
}

int magic_set_log_console_fd(const void *val, struct pink_easy_process *current)
{
	log_console_fd(PTR_TO_INT(val));
	return 0;
}

int magic_set_log_console_level(const void *val, struct pink_easy_process *current)
{
	log_debug_console_level(PTR_TO_INT(val));
	return 0;
}
