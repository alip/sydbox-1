/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Pandora's Box. pandora is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pandora is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "pandora-defs.h"

#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"

int magic_set_log_file(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	const char *str = val;

	if (!str /* || !*str */)
		return MAGIC_ERROR_INVALID_VALUE;

	log_close();

	if (!*str) {
		if (pandora->config.log_file)
			free(pandora->config.log_file);
		pandora->config.log_file = NULL;
		return 0;
	}

	if (pandora->config.log_file)
		free(pandora->config.log_file);
	pandora->config.log_file = xstrdup(str);

	log_init();

	return 0;
}

int magic_set_log_console_fd(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int r = PTR_TO_INT(val);

	if (r < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.log_console_fd = r;
	return 0;
}

int magic_set_log_level(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int r;
	const char *str = val;

	if ((r = log_level_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.log_level = r;
	return 0;
}

int magic_set_log_timestamp(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.log_timestamp = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_log_timestamp(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return pandora->config.log_timestamp;
}
