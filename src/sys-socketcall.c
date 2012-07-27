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

#include <errno.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_socketcall(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long subcall;
	pid_t tid = pink_easy_process_get_tid(current);
	pink_abi_t abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_sock_off(data))
		return 0;

	if (!pink_read_socket_subcall(tid, abi, data->regs, true, &subcall)) {
		if (errno != ESRCH) {
			warning("pink_read_socket_subcall(%lu, %d, true) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
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

int sysx_socketcall(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_sock_off(data))
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
