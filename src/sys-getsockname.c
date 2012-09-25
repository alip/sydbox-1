/*
 * sydbox/sys-getsockname.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"
#include "log.h"

int sys_getsockname(struct pink_easy_process *current, const char *name)
{
	bool decode_socketcall;
	long fd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data)
	    || !sydbox->config.whitelist_successful_bind)
		return 0;

	decode_socketcall = !!(data->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if (!pink_read_socket_argument(tid, abi, &data->regs,
				       decode_socketcall, 0, &fd)) {
		if (errno != ESRCH) {
			log_warning("read_socket_argument(%lu, %d, %s, 0)"
				    " failed (errno:%d %s)",
				    (unsigned long)tid, abi,
				    decode_socketcall ? "true" : "false",
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_socket_argument(%lu, %d, %s, 0)"
			  " failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  decode_socketcall ? "true" : "false",
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap, fd + 1, 0);
	if (node)
		data->args[0] = fd;

	return 0;
}

int sysx_getsockname(struct pink_easy_process *current, const char *name)
{
	bool decode_socketcall;
	unsigned port;
	long retval;
	struct pink_sockaddr psa;
	struct snode *snode;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data)
	    || !sydbox->config.whitelist_successful_bind
	    || !data->args[0])
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
		return 0;
	}

	decode_socketcall = !!(data->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if (!pink_read_socket_address(tid, abi, &data->regs,
				      decode_socketcall,
				      1, NULL, &psa)) {
		if (errno != ESRCH) {
			log_warning("read_socket_address(%lu, %d, %s, 0)"
				    " failed (errno:%d %s)",
				    (unsigned long)tid, abi,
				    decode_socketcall ? "true" : "false",
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_socket_address(%lu, %d, %s, 0) failed"
			  " (errno:%d %s)",
			  (unsigned long)tid, abi,
			  decode_socketcall ? "true" : "false",
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]", data->comm,
			  (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap,
					       data->args[0] + 1, 0);
	assert(node);
	struct sockinfo *info = node->data;
	struct sockmatch *match = sockmatch_new(info);

	free_sockinfo(info);
	node->key = 0;
	node->data = NULL;

	switch (match->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		/* assert(port); */
		match->addr.sa_in.port[0] = match->addr.sa_in.port[1] = port;
		break;
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		/* assert(port); */
		match->addr.sa6.port[0] = match->addr.sa6.port[1] = port;
		break;
#endif
	default:
		assert_not_reached();
	}

	log_trace("whitelist bind() address with port:0->%u"
		  " for process %s[%lu:%u]",
		  port, data->comm, (unsigned long)tid, abi);
	snode = xcalloc(1, sizeof(struct snode));
	snode->data = match;
	SLIST_INSERT_HEAD(&data->config.whitelist_network_connect, snode, up);
	return 0;
}
