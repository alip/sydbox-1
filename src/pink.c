/*
 * sydbox/pink.c
 *
 * pinktrace wrapper functions
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <errno.h>
#include <string.h>
#include <pinktrace/pink.h>
#include "log.h"

int syd_trace_detach(syd_proc_t *current, int sig)
{
	int r;

	assert(current);

	r = pink_trace_detach(GET_PID(current), sig);
	if (r == 0)
		log_trace("DETACH sig:%d", sig);
	else if (r == -ESRCH)
		err_trace(-r, "trace_detach(sig:%d) failed", sig);
	else
		err_warning(-r, "trace_detach(sig:%d) failed", sig);

	ignore_proc(current);
	return r;
}

int syd_trace_kill(syd_proc_t *current, int sig)
{
	int r;

	assert(current);

	r = pink_trace_kill(GET_PID(current), current->tgid, sig);
	if (r == 0)
		log_trace("KILL sig:%d", sig);
	else if (r == -ESRCH)
		err_trace(-r, "trace_kill(sig:%d) failed", sig);
	else
		err_warning(-r, "trace_kill(sig:%d) failed", sig);

	ignore_proc(current);
	return r;
}

int syd_trace_setup(syd_proc_t *current)
{
	int r;
	int opts = sydbox->trace_options;

	assert(current);

	log_trace("setting trace options 0x%x", opts);
	r = pink_trace_setup(GET_PID(current), opts);
	if (r == -ESRCH)
		err_trace(-r, "trace_setup() failed");
	else if (r < 0)
		err_warning(-r, "trace_setup() failed");
	return r;
}

int syd_trace_geteventmsg(syd_proc_t *current, unsigned long *data)
{
	int r;

	assert(current);

	r = pink_trace_geteventmsg(GET_PID(current), data);
	if (r == -ESRCH)
		err_trace(-r, "trace_geteventmsg() failed");
	else if (r < 0)
		err_warning(-r, "trace_geteventmsg() failed");
	return r;
}

int syd_read_syscall(syd_proc_t *current, long *sysnum)
{
	int r;

	assert(current);
	assert(sysnum);

	r = pink_read_syscall(current->pink, sysnum);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_syscall() failed");
	else if (r < 0)
		err_warning(-r, "read_syscall() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_read_retval(syd_proc_t *current, long *retval, int *error)
{
	int r;

	assert(current);

	r = pink_read_retval(current->pink, retval, error);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_retval() failed");
	else if (r < 0)
		err_warning(-r, "read_retval() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_read_argument(syd_proc_t *current, unsigned arg_index, long *argval)
{
	int r;

	assert(current);
	assert(argval);

	r = pink_read_argument(current->pink, arg_index, argval);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_argument() failed");
	else if (r < 0)
		err_warning(-r, "read_argument() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

ssize_t syd_read_string(syd_proc_t *current, long addr, char *dest, size_t len)
{
	ssize_t r;
	int save_errno;

	assert(current);

	r = pink_read_string(current->pink, addr, dest, len);
	save_errno = errno;
	if (r < 0) {
		if (save_errno == EFAULT)
			log_trace("read_string() hit NULL pointer");
		else if (save_errno != ESRCH)
			save_errno = panic(current);
		errno = save_errno;
		return -1;
	} else if ((size_t)r == len) {
		return r;
	} else { /* partial read */
		err_trace(save_errno, "read_string() partial read");
		dest[r - 1] = '\0';
		errno = 0;
		return r;
	}
}

int syd_read_socket_argument(syd_proc_t *current, bool decode_socketcall,
			     unsigned arg_index, unsigned long *argval)
{
	int r;

	assert(current);
	assert(argval);

	r = pink_read_socket_argument(current->pink, decode_socketcall,
				      arg_index, argval);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_socket_argument() failed");
	else if (r < 0)
		err_warning(-r, "read_socket_argument() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_read_socket_subcall(syd_proc_t *current, bool decode_socketcall,
			    long *subcall)
{
	int r;

	assert(current);

	r = pink_read_socket_subcall(current->pink, decode_socketcall, subcall);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_socket_subcall() failed");
	else if (r < 0)
		err_warning(-r, "read_socket_subcall() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_read_socket_address(syd_proc_t *current, bool decode_socketcall,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr)
{
	int r;

	assert(current);
	assert(sockaddr);

	r = pink_read_socket_address(current->pink, decode_socketcall,
				     arg_index, fd, sockaddr);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "read_socket_address() failed");
	else if (r < 0)
		err_warning(-r, "read_socket_address() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_write_syscall(syd_proc_t *current, long sysnum)
{
	int r;

	assert(current);

	r = pink_write_syscall(current->pink, sysnum);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "write_syscall() failed");
	else if (r < 0)
		err_warning(-r, "write_syscall() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}

int syd_write_retval(syd_proc_t *current, long retval, int error)
{
	int r;

	assert(current);

	r = pink_write_retval(current->pink, retval, error);
	if (r == 0)
		return 0;
	else if (r == -ESRCH)
		err_trace(-r, "write_retval() failed");
	else if (r < 0)
		err_warning(-r, "write_retval() failed");
	return (r == -ESRCH) ? -ESRCH : panic(current);
}
