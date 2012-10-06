/*
 * sydbox/util.c
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright 2010 Lennart Poettering
 * Based in part upon courier which is:
 *   Copyright 1998-2009 Double Precision, Inc
 * Distributed under the terms of the GNU General Public License v2
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "log.h"
#include "util.h"

int safe_atoi(const char *s, int *ret_i)
{
	char *x = NULL;
	long l;

	errno = 0;
	l = strtol(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	if ((long) (int) l != l)
		return -ERANGE;

	*ret_i = (int) l;
	return 0;
}

int safe_atou(const char *s, unsigned *ret_u)
{
	char *x = NULL;
	unsigned long l;

	assert(s);
	assert(ret_u);

	errno = 0;
	l = strtoul(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	if ((unsigned long) (unsigned) l != l)
		return -ERANGE;

	*ret_u = (unsigned) l;
	return 0;
}

int safe_atollu(const char *s, long long unsigned *ret_llu)
{
	char *x = NULL;
	unsigned long long l;

	assert(s);
	assert(ret_llu);

	errno = 0;
	l = strtoull(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	*ret_llu = l;
	return 0;
}

int parse_boolean(const char *s, bool *ret_bool)
{
	bool b;

	assert(s);
	assert(ret_bool);

	if (streq(s, "1") || streqcase(s, "t") || streqcase(s, "true"))
		b = true;
	else if (streq(s, "0") || streqcase(s, "f") || streqcase(s, "false"))
		b = false;
	else
		return -EINVAL;

	*ret_bool = b;
	return 0;
}

int parse_pid(const char *s, pid_t *ret_pid)
{
	unsigned long ul;
	pid_t pid;
	int r;

	assert(s);
	assert(ret_pid);

	if ((r = safe_atolu(s, &ul)) < 0)
		return r;

	pid = (pid_t) ul;

	if ((unsigned long) pid != ul)
		return -ERANGE;

	if (pid <= 0)
		return -ERANGE;

	*ret_pid = pid;
	return 0;
}

int parse_port(const char *s, unsigned *ret_port)
{
	int r;
	unsigned port;
	struct servent *service;

	assert(s);
	assert(ret_port);

	if (!*s)
		return -EINVAL;

	if (isdigit(*s)) {
		/* Looks like a digit! */
		if ((r = safe_atou(s, &port)) < 0)
			return r;

		if (port > 65535)
			return -ERANGE;
	}
	else {
		/* Looks like a service name! */
		if (!(service = getservbyname(s, NULL)))
			return -EINVAL;

		port = ntohs(service->s_port);
	}

	*ret_port = port;
	return 0;
}

int parse_netmask_ip(const char *addr, unsigned *ret_netmask)
{
	unsigned netmask;
	const char *p;

	assert(ret_netmask);

	netmask = 8;
	p = addr;
	while (*p != 0) {
		if (*p++ == '.') {
			if (*p == 0)
				break;
			netmask += 8;
		}
	}

	*ret_netmask = netmask;
	return 0;
}

int parse_netmask_ipv6(const char *addr, unsigned *ret_netmask)
{
	unsigned netmask;
	const char *p;

	assert(ret_netmask);

	netmask = 16;
	p = addr;
	while (*p != 0) {
		if (*p++ == ':') {
			/* ip:: ends the prefix right here,
			 * but ip::ip is a full IPv6 address.
			 */
			if (p[1] != '\0')
				netmask = sizeof(struct in6_addr) * 8;
			break;
		}
		if (*p == 0)
			break;
		netmask += 16;
	}

	*ret_netmask = netmask;
	return 0;
}

bool endswith(const char *s, const char *postfix)
{
	size_t sl, pl;

	assert(s);
	assert(postfix);

	sl = strlen(s);
	pl = strlen(postfix);

	if (pl == 0)
		return true;

	if (sl < pl)
		return false;

	return memcmp(s + sl - pl, postfix, pl) == 0;
}

bool startswith(const char *s, const char *prefix)
{
	size_t sl, pl;

	assert(s);
	assert(prefix);

	sl = strlen(s);
	pl = strlen(prefix);

	if (pl == 0)
		return true;

	if (sl < pl)
		return false;

	return memcmp(s, prefix, pl) == 0;
}

int close_nointr(int fd)
{
	assert(fd >= 0);

	for (;;) {
		int r;

		r = close(fd);
		if (fd >= 0)
			return r;

		if (errno != EINTR)
			return r;
	}
	/* never reached */
}

int waitpid_nointr(pid_t pid, int *status, int options)
{
	assert(pid >= 0);

	for (;;) {
		int r;

		r = waitpid(pid, status, options);
		if (r >= 0)
			return r;

		if (errno != EINTR)
			return r;
	}
	/* never reached */
}
