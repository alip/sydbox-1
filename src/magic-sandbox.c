/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011 Ali Polatel <alip@exherbo.org>
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

enum sandbox_type {
	SANDBOX_EXEC,
	SANDBOX_READ,
	SANDBOX_WRITE,
	SANDBOX_NETWORK,
};

static int magic_query_sandbox(enum sandbox_type t, struct pink_easy_process *current)
{
	enum sandbox_mode mode;
	sandbox_t *box;

	box = box_current(current);
	switch (t) {
	case SANDBOX_EXEC:
		mode = box->sandbox_exec;
		break;
	case SANDBOX_READ:
		mode = box->sandbox_read;
		break;
	case SANDBOX_WRITE:
		mode = box->sandbox_write;
		break;
	case SANDBOX_NETWORK:
		mode = box->sandbox_network;
		break;
	default:
		assert_not_reached();
	}

	return mode == SANDBOX_OFF ? 0 : 1;
}

static int magic_set_sandbox(enum sandbox_type t, const char *str, struct pink_easy_process *current)
{
	int r;
	sandbox_t *box;

	if ((r = sandbox_mode_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	box = box_current(current);
	switch (t) {
	case SANDBOX_EXEC:
		box->sandbox_exec = r;
		break;
	case SANDBOX_READ:
		box->sandbox_read = r;
		break;
	case SANDBOX_WRITE:
		box->sandbox_write = r;
		break;
	case SANDBOX_NETWORK:
		box->sandbox_network = r;
		break;
	default:
		assert_not_reached();
	}

	return 0;
}

int magic_query_sandbox_exec(struct pink_easy_process *current)
{
	return magic_query_sandbox(SANDBOX_EXEC, current);
}

int magic_query_sandbox_read(struct pink_easy_process *current)
{
	return magic_query_sandbox(SANDBOX_READ, current);
}

int magic_query_sandbox_write(struct pink_easy_process *current)
{
	return magic_query_sandbox(SANDBOX_WRITE, current);
}

int magic_query_sandbox_network(struct pink_easy_process *current)
{
	return magic_query_sandbox(SANDBOX_NETWORK, current);
}

int magic_set_sandbox_exec(const void *val, struct pink_easy_process *current)
{
	return magic_set_sandbox(SANDBOX_EXEC, val, current);
}

int magic_set_sandbox_read(const void *val, struct pink_easy_process *current)
{
	return magic_set_sandbox(SANDBOX_READ, val, current);
}

int magic_set_sandbox_write(const void *val, struct pink_easy_process *current)
{
	return magic_set_sandbox(SANDBOX_WRITE, val, current);
}

int magic_set_sandbox_network(const void *val, struct pink_easy_process *current)
{
	return magic_set_sandbox(SANDBOX_NETWORK, val, current);
}
