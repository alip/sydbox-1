/*
 * sydbox/magic-log.c
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
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
			die_errno("log_init for file `%s' failed", filename);
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
	int r;
	int fd = PTR_TO_INT(val);

	if ((r = log_console_fd(fd)) < 0) {
		errno = -r;
		die_errno("log_console_fd for fd `%d' failed", fd);
	}

	return 0;
}

int magic_set_log_console_level(const void *val, struct pink_easy_process *current)
{
	log_debug_console_level(PTR_TO_INT(val));
	return 0;
}
