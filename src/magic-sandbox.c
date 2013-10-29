/*
 * sydbox/magic-sandbox.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdlib.h>

#include <pinktrace/pink.h>

#include "macro.h"

enum sandbox_type {
	SANDBOX_EXEC,
	SANDBOX_READ,
	SANDBOX_WRITE,
	SANDBOX_NETWORK,
};

static int magic_query_sandbox(enum sandbox_type t, syd_process_t *current)
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

	return MAGIC_BOOL(mode != SANDBOX_OFF);
}

static int magic_set_sandbox(enum sandbox_type t, const char *str, syd_process_t *current)
{
	int r;
	sandbox_t *box;

	r = sandbox_mode_from_string(str);
	if (r < 0)
		return MAGIC_RET_INVALID_VALUE;

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

	return MAGIC_RET_OK;
}

int magic_query_sandbox_exec(syd_process_t *current)
{
	return magic_query_sandbox(SANDBOX_EXEC, current);
}

int magic_query_sandbox_read(syd_process_t *current)
{
	return magic_query_sandbox(SANDBOX_READ, current);
}

int magic_query_sandbox_write(syd_process_t *current)
{
	return magic_query_sandbox(SANDBOX_WRITE, current);
}

int magic_query_sandbox_network(syd_process_t *current)
{
	return magic_query_sandbox(SANDBOX_NETWORK, current);
}

int magic_set_sandbox_exec(const void *val, syd_process_t *current)
{
	return magic_set_sandbox(SANDBOX_EXEC, val, current);
}

int magic_set_sandbox_read(const void *val, syd_process_t *current)
{
	return magic_set_sandbox(SANDBOX_READ, val, current);
}

int magic_set_sandbox_write(const void *val, syd_process_t *current)
{
	return magic_set_sandbox(SANDBOX_WRITE, val, current);
}

int magic_set_sandbox_network(const void *val, syd_process_t *current)
{
	return magic_set_sandbox(SANDBOX_NETWORK, val, current);
}
