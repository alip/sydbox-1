/*
 * sydbox/sys-connect.c
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/queue.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_connect(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_network_off(data))
		return 0;

	init_sysinfo(&info);
	info.access_mode = sandbox_network_deny(data)
			   ? ACCESS_WHITELIST
			   : ACCESS_BLACKLIST;
	info.access_list = sandbox_network_deny(data)
			   ? &data->config.whitelist_network_connect
			   : &data->config.blacklist_network_connect;
	info.access_filter = &sydbox->config.filter_network;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.arg_index = 1;
	info.deny_errno = ECONNREFUSED;
	if (data->subcall == PINK_SOCKET_SUBCALL_CONNECT)
		info.decode_socketcall = true;

	return box_check_socket(current, name, &info);
}

int sys_sendto(struct pink_easy_process *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sysinfo_t info;

	if (sandbox_network_off(data))
		return 0;

	init_sysinfo(&info);
	info.access_mode = sandbox_network_deny(data)
			   ? ACCESS_WHITELIST
			   : ACCESS_BLACKLIST;
	info.access_list = sandbox_network_deny(data)
			   ? &data->config.whitelist_network_connect
			   : &data->config.blacklist_network_connect;
	info.access_filter = &sydbox->config.filter_network;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.arg_index = 4;
	info.deny_errno = ECONNREFUSED;
	if (data->subcall == PINK_SOCKET_SUBCALL_SENDTO)
		info.decode_socketcall = true;

	return box_check_socket(current, name, &info);
}
