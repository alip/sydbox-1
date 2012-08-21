/*
 * sydbox/sys-socketcall.c
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

int sys_socketcall(struct pink_easy_process *current, const char *name)
{
	long subcall;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data))
		return 0;

	if (!pink_read_socket_subcall(tid, abi, &data->regs, true, &subcall)) {
		if (errno != ESRCH) {
			log_warning("read_socket_subcall(%lu, %d, true) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    errno, strerror(errno));
			return panic(current);
		}
		log_trace("read_socket_subcall(%lu, %d, true) failed"
			  "(errno:%d %s)",
			  (unsigned long)tid, abi,
			  errno, strerror(errno));
		log_trace("drop process %s[%lu:%u]",
			  data->comm, (unsigned long)tid, abi);
		return PINK_EASY_CFLAG_DROP;
	}

	data->subcall = subcall;

	switch (subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sys_bind(current, "bind");
	case PINK_SOCKET_SUBCALL_CONNECT:
		return sys_connect(current, "connect");
	case PINK_SOCKET_SUBCALL_SENDTO:
		return sys_sendto(current, "sendto");
	case PINK_SOCKET_SUBCALL_RECVFROM:
		return sys_recvfrom(current, "recvfrom");
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sys_getsockname(current, "getsockname");
	default:
		return 0;
	}
}

int sysx_socketcall(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data))
		return 0;

	switch (data->subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sysx_bind(current, "bind");
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sysx_getsockname(current, "getsockname");
	default:
		return 0;
	}
}
