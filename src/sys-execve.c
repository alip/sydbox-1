/*
 * sydbox/sys-execve.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "log.h"
#include "pathdecode.h"
#include "strtable.h"

int sys_execve(struct pink_easy_process *current, const char *name)
{
	int r;
	char *path, *abspath;
	pid_t tid;
	enum pink_abi abi;
	proc_data_t *data;

	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	data = pink_easy_process_get_userdata(current);
	path = abspath = NULL;

	r = path_decode(current, 0, &path);
	if (r < 0)
		return deny(current, errno);
	else if (r /* > 0 */)
		return r;

	r = box_resolve_path(path, data->cwd, tid, CAN_EXISTING, &abspath);
	if (r < 0) {
		log_access("resolve path=`%s' failed (errno=%d %s)",
			   path, -r, strerror(-r));
		log_access("access denied with errno=%s",
			   errno_to_string(-r));
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(\"%s\")", name, path);
		free(path);
		return r;
	}
	free(path);

	/* Handling exec.kill_if_match and exec.resume_if_match:
	 *
	 * Resolve and save the path argument in data->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	data->abspath = abspath;

	switch (data->config.sandbox_exec) {
	case SANDBOX_OFF:
		return 0;
	case SANDBOX_DENY:
		if (box_match_path(&data->config.whitelist_exec, abspath,
				   NULL))
			return 0;
		break;
	case SANDBOX_ALLOW:
		if (!box_match_path(&data->config.blacklist_exec, abspath,
				    NULL))
			return 0;
		break;
	default:
		assert_not_reached();
	}

	r = deny(current, EACCES);

	if (!box_match_path(&sydbox->config.filter_exec, abspath, NULL))
		violation(current, "%s(\"%s\")", name, abspath);

	free(abspath);
	data->abspath = NULL;

	return r;
}
