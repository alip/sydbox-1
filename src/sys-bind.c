/*
 * sydbox/sys-bind.c
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

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
	unsigned long fd;
	char *unix_abspath;
	struct pink_sockaddr *psa;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_network_off(data))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.deny_errno = EADDRNOTAVAIL;
	if (data->subcall == PINK_SOCKET_SUBCALL_BIND)
		info.decode_socketcall = true;
	if (sandbox_network_deny(data)) {
		info.access_mode = ACCESS_WHITELIST;
		info.access_list = &data->config.whitelist_network_bind;
	} else {
		info.access_mode = ACCESS_BLACKLIST;
		info.access_list = &data->config.blacklist_network_bind;
	}
	info.access_filter = &sydbox->config.filter_network;

	if (sydbox->config.whitelist_successful_bind) {
		info.ret_abspath = &unix_abspath;
		info.ret_addr = &psa;
	}

	r = box_check_socket(current, name, &info);

	if (r == 0 && sydbox->config.whitelist_successful_bind) {
		/* Access granted.
		 * Read the file descriptor, for use in exit.
		 */
		int pf;
		if ((pf = pink_read_socket_argument(tid, abi, &data->regs,
						    info.decode_socketcall, 0,
						    &fd)) < 0) {
			if (pf != -ESRCH) {
				log_warning("read_socket_argument(%lu, %d, %s, 0) failed"
					    " (errno:%d %s)",
					    (unsigned long)tid, abi,
					    info.decode_socketcall ? "true" : "false",
					    -r, strerror(-r));
				return panic(current);
			}
			log_trace("read_socket_argument(%lu, %d, %s, 0) failed"
				  " (errno:%d %s)",
				  (unsigned long)tid, abi,
				  info.decode_socketcall ? "true" : "false",
				  -r, strerror(-r));
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
			data->savebind = xmalloc(sizeof(struct sockinfo));
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
	int r;
	long retval;
	struct snode *snode;
	ht_int64_node_t *node;
	struct sockmatch *match;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) ||
	    !sydbox->config.whitelist_successful_bind ||
	    !data->savebind)
		return 0;

	/* Check the return value */
	if ((r = pink_read_retval(tid, abi, &data->regs, &retval, NULL)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_retval(%lu, %d) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -r, strerror(-r));
			return panic(current);
		}
		log_trace("read_retval(%lu, %d) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -r, strerror(-r));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		log_trace("ignore failed %s() call for process %s[%lu:%u]",
			  name, data->comm, (unsigned long)tid, abi);
		free_sockinfo(data->savebind);
		data->savebind = NULL;
		return 0;
	}

	/* Check for bind() with zero as port argument */
	if (data->savebind->addr->family == AF_INET
	    && data->savebind->addr->u.sa_in.sin_port == 0)
		goto zero;
#if SYDBOX_HAVE_IPV6
	if (data->savebind->addr->family == AF_INET6
	    && data->savebind->addr->u.sa6.sin6_port == 0)
		goto zero;
#endif

	log_trace("whitelist bind() address by process %s[%lu:%u]",
		  data->comm, (unsigned long)tid, abi);
	snode = xcalloc(1, sizeof(struct snode));
	match = sockmatch_new(data->savebind);
	snode->data = match;
	SLIST_INSERT_HEAD(&sydbox->config.whitelist_network_connect_auto,
			  snode, up);
	return 0;
zero:
	node = hashtable_find(data->sockmap, data->args[0] + 1, 1);
	if (!node)
		die_errno("hashtable_find");
	node->data = data->savebind;
	data->savebind = NULL;
	return 0;
}
