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

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"

int magic_set_log_file(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	const char *str = val;

	if (!str /* || !*str */)
		return MAGIC_ERROR_INVALID_VALUE;

	log_close();

	if (!*str) {
		if (sydbox->config.log_file)
			free(sydbox->config.log_file);
		sydbox->config.log_file = NULL;
		return 0;
	}

	if (sydbox->config.log_file)
		free(sydbox->config.log_file);
	sydbox->config.log_file = xstrdup(str);

	log_init();

	return 0;
}

int magic_set_log_console_fd(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	int r = PTR_TO_INT(val);

	if (r < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.log_console_fd = r;
	return 0;
}

int magic_set_log_level(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	int r = PTR_TO_INT(val);

	if (r < 0 || r > 5)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.log_level = r;
	return 0;
}

int magic_set_log_timestamp(const void *val, PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	sydbox->config.log_timestamp = PTR_TO_BOOL(val);
	return 0;
}

int magic_query_log_timestamp(PINK_GCC_ATTR((unused)) struct pink_easy_process *current)
{
	return sydbox->config.log_timestamp;
}
