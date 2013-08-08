/*
 * sydbox/magic-log.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdlib.h>
#include <errno.h>
#include <pinktrace/pink.h>

#include "log.h"
#include "macro.h"

int magic_set_log_file(const void *val, syd_proc_t *current)
{
	const char *filename = val;

	if (!filename /* || !*filename */)
		return MAGIC_RET_INVALID_VALUE;

	log_close();

	if (*filename) {
		int r;

		if ((r = log_init(filename)) < 0) {
			errno = -r;
			die_errno("log_init for file `%s' failed", filename);
		}
	} else {
		log_init(NULL);
	}

	return MAGIC_RET_OK;
}

int magic_set_log_level(const void *val, syd_proc_t *current)
{
	log_debug_level(PTR_TO_INT(val));
	return MAGIC_RET_OK;
}

int magic_set_log_console_fd(const void *val, syd_proc_t *current)
{
	int r;
	int fd = PTR_TO_INT(val);

	if ((r = log_console_fd(fd)) < 0) {
		errno = -r;
		die_errno("log_console_fd for fd `%d' failed", fd);
	}

	return MAGIC_RET_OK;
}

int magic_set_log_console_level(const void *val, syd_proc_t *current)
{
	log_debug_console_level(PTR_TO_INT(val));
	return MAGIC_RET_OK;
}
