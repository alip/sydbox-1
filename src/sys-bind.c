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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <sys/un.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"
#include "log.h"

int sys_bind(struct pink_easy_process *current, const char *name)
{
	int r;
	long fd;
	char *unix_abspath;
	struct pink_sockaddr *psa;
	sys_info_t info;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data))
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelisting = data->config.sandbox_network == SANDBOX_DENY;
	info.wblist = sandbox_network_deny(data) ? &data->config.whitelist_network_bind : &data->config.blacklist_network_bind;
	info.filter = &sydbox->config.filter_network;
	info.resolve = true;
	info.arg_index = 1;
	info.create = MAY_CREATE;
	info.deny_errno = EADDRNOTAVAIL;

	if (data->subcall == PINK_SOCKET_SUBCALL_BIND)
		info.decode_socketcall = true;

	if (sydbox->config.whitelist_successful_bind) {
		info.abspath = &unix_abspath;
		info.addr = &psa;
	}

	r = box_check_socket(current, name, &info);

	if (sydbox->config.whitelist_successful_bind && !r) {
		/* Read the file descriptor, for use in exit */
		if (!pink_read_argument(tid, abi, &data->regs, 0, &fd)) {
			if (errno != ESRCH) {
				log_warning("read_argument(%lu, %d, 0) failed"
						" (errno:%d %s)",
						(unsigned long)tid, abi,
						errno, strerror(errno));
				return panic(current);
			}
			log_trace("read_argument(%lu, %d, 0) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			log_trace("drop process %s[%lu:%u]",
					data->comm, (unsigned long)tid, abi);
			return PINK_EASY_CFLAG_DROP;
		}
		data->args[0] = fd;

		switch (psa->family) {
		case AF_UNIX:
		case AF_INET:
#if SYDBOX_HAVE_IPV6
		case AF_INET6:
#endif /* SYDBOX_HAVE_IPV6 */
			data->savebind = xmalloc(sizeof(sock_info_t));
			data->savebind->path = unix_abspath;
			data->savebind->addr = psa;
			/* fall through */
		default:
			return r;
		}
	}

	if (sydbox->config.whitelist_successful_bind) {
		if (unix_abspath)
			free(unix_abspath);
		if (psa)
			free(psa);
	}

	return r;
}

int sysx_bind(struct pink_easy_process *current, const char *name)
{
	long retval;
	struct snode *snode;
	ht_int64_node_t *node;
	sock_match_t *m;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) || !sydbox->config.whitelist_successful_bind || !data->savebind)
		return 0;

	/* Check the return value */
	if (!pink_read_retval(tid, abi, &data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			log_warning("read_retval(%lu, %d) failed"
					" (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_retval(%lu, %d) failed (errno:%d %s)",
				(unsigned long)tid, abi,
				errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
				data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		log_trace("ignore failed %s() call for process %s[%lu:%u]",
				name, data->comm, (unsigned long)tid,
				abi);
		free_sock_info(data->savebind);
		data->savebind = NULL;
		return 0;
	}

	/* Check for bind() with zero as port argument */
	if (data->savebind->addr->family == AF_INET && !data->savebind->addr->u.sa_in.sin_port)
		goto zero;
#if SYDBOX_HAVE_IPV6
	if (data->savebind->addr->family == AF_INET6 && !data->savebind->addr->u.sa6.sin6_port)
		goto zero;
#endif

	snode = xcalloc(1, sizeof(struct snode));
	sock_match_new_pink(data->savebind, &m);
	snode->data = m;
	SLIST_INSERT_HEAD(&data->config.whitelist_network_connect, snode, up);
	return 0;
zero:
	node = hashtable_find(data->sockmap, data->args[0] + 1, 1);
	if (!node)
		die_errno(-1, "hashtable_find");
	node->data = data->savebind;
	data->savebind = NULL;
	return 0;
}
