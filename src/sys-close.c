/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
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

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

int sys_close(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long fd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) || !sydbox->config.whitelist_successful_bind)
		return 0;

	if (!pink_read_argument(tid, abi, data->regs, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 0) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (hashtable_find(data->sockmap, fd + 1, 0))
		data->args[0] = fd;

	return 0;
}

int sysx_close(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long retval;
	ht_int64_node_t *node;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) || !sydbox->config.whitelist_successful_bind || !data->args[0])
		return 0;

	if (!pink_read_retval(tid, abi, data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			warning("pink_read_retval(%lu, %d) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		debug("ignoring failed %s() call for process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"]",
				name, (unsigned long)tid, abi,
				data->comm, data->cwd);
		return 0;
	}

	node = hashtable_find(data->sockmap, data->args[0] + 1, 0);
	assert(node);

	node->key = 0;
	free_sock_info(node->data);
	node->data = NULL;
	info("process:%lu [abi:%d name:\"%s\" cwd:\"%s\"] closed fd:%lu by %s() call",
			(unsigned long)tid, abi,
			data->comm, data->cwd, data->args[0], name);
	return 0;
}
