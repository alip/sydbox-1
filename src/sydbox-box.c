/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "canonicalize.h"
#include "path.h"
#include "proc.h"
#include "strtable.h"
#include "util.h"

static inline void box_report_violation_path(struct pink_easy_process *current,
		const char *name, unsigned ind, const char *path)
{
	switch (ind) {
	case 0:
		violation(current, "%s('%s')", name, path);
		break;
	case 1:
		violation(current, "%s(?, '%s')", name, path);
		break;
	case 2:
		violation(current, "%s(?, ?, '%s')", name, path);
		break;
	case 3:
		violation(current, "%s(?, ?, ?, '%s')", name, path);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static inline void box_report_violation_path_at(struct pink_easy_process *current,
		const char *name, unsigned arg_index, const char *path,
		const char *prefix)
{
	switch (arg_index) {
	case 1:
		violation(current, "%s('%s', prefix='%s')", name, path, prefix);
		break;
	case 2:
		violation(current, "%s(?, '%s', prefix='%s')", name, path, prefix);
		break;
	case 3:
		violation(current, "%s(?, ?, '%s', prefix='%s')", name, path, prefix);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static void box_report_violation_sock(struct pink_easy_process *current,
		const sys_info_t *info, const char *name,
		const struct pink_sockaddr *paddr)
{
	char ip[64];
	const char *f;

	switch (paddr->family) {
	case AF_UNIX:
		violation(current, "%s(%ld, %s:%s)",
				name,
				info->fd ? *info->fd : -1,
				*paddr->u.sa_un.sun_path ? "unix" : "unix-abstract",
				*paddr->u.sa_un.sun_path
					? paddr->u.sa_un.sun_path
					: paddr->u.sa_un.sun_path + 1);
		break;
	case AF_INET:
		inet_ntop(AF_INET, &paddr->u.sa_in.sin_addr, ip, sizeof(ip));
		violation(current, "%s(%ld, inet:%s@%d)",
				name,
				info->fd ? *info->fd : -1,
				ip, ntohs(paddr->u.sa_in.sin_port));
		break;
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
		inet_ntop(AF_INET6, &paddr->u.sa6.sin6_addr, ip, sizeof(ip));
		violation(current, "%s(%ld, inet6:%s@%d)",
				name,
				info->fd ? *info->fd : -1,
				ip, ntohs(paddr->u.sa6.sin6_port));
		break;
#endif
	default:
		f = address_family_to_string(paddr->family);
		violation(current, "%s(-1, ?:%s)", name, f ? f : "AF_???");
		break;
	}
}

static int box_resolve_path_helper(const char *abspath, pid_t pid,
		int maycreat, int resolve, char **res)
{
	int r;
	char *p;
	can_mode_t can_mode;

	p = NULL;
	/* Special case for /proc/self.
	 * This symbolic link resolves to /proc/$pid, if we let
	 * canonicalize_filename_mode() resolve this, we'll get a different result.
	 */
	if (startswith(abspath, "/proc/self")) {
		const char *tail = abspath + STRLEN_LITERAL("/proc/self");
		if (!*tail || *tail == '/') {
			if (asprintf(&p, "/proc/%lu%s", (unsigned long)pid, tail) < 0)
				return -errno;
		}
	}

	can_mode = maycreat ? CAN_ALL_BUT_LAST : CAN_EXISTING;
	if (!resolve)
		can_mode |= CAN_NOLINKS;
	r = canonicalize_filename_mode(p ? p : abspath, can_mode, res);
	if (p)
		free(p);
	return r;
}

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		int maycreat, int resolve, char **res)
{
	int r;
	char *abspath;

	abspath = path != NULL ? path_make_absolute(path, prefix) : xstrdup(prefix);
	if (!abspath)
		return -errno;

	r = box_resolve_path_helper(abspath, pid, maycreat, resolve, res);
	free(abspath);
	return r;
}

int box_match_path(const char *path, const slist_t *patterns, const char **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (wildmatch_syd(node->data, path)) {
			debug("match: pattern='%s', path='%s'",
					(char *)node->data,
					path);
			if (match)
				*match = node->data;
			return 1;
		}
		debug("nomatch: pattern='%s', path='%s'",
				(char *)node->data,
				path);
	}

	return 0;
}

int box_check_path(struct pink_easy_process *current, const char *name, sys_info_t *info)
{
	int r;
	char *prefix, *path, *abspath;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	slist_t *wblist;

	debug("check_path: %s[%lu:%u] sys:%s() arg_index:%u cwd:'%s'",
			data->comm, (unsigned long)tid, abi, name,
			info->arg_index, data->cwd);
	debug("check_path: at:%s null_ok:%s resolve:%s create:%s",
			info->at ? "true" : "false",
			info->null_ok ? "true" : "false",
			info->resolve ? "true" : "false",
			create_mode_to_string(info->create));
	debug("check_path: safe:%s deny-errno:%s whitelisting:%s",
			info->safe ? "true" : "false",
			errno_to_string(info->deny_errno),
			info->whitelisting ? "true" : "false");

	assert(current);
	assert(info);

	prefix = path = abspath = NULL;

	if (info->at && (r = path_prefix(current, info->arg_index - 1, &prefix))) {
		if (r < 0) {
			errno = -r;
			r = deny(current);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
		}
		return r;
	}

	r = path_decode(current, info->arg_index, &path);
	if (r < 0 && !(info->at && info->null_ok && prefix && r == -EFAULT)) {
		errno = -r;
		r = deny(current);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto out;
	} else if (r > 0 /* PINK_EASY_CFLAG */) {
		goto out;
	}

	if ((r = box_resolve_path(path, prefix ? prefix : data->cwd,
					tid,
					!!(info->create > 0),
					info->resolve, &abspath)) < 0) {
		info("check_path: resolve path:'%s' for sys:%s() failed (errno:%d %s)",
				path, name, -r, strerror(-r));
		errno = -r;
		r = deny(current);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto out;
	}
	debug("check_path: resolve path:'%s' for sys:%s() succeeded", path, name);

	if (info->wblist)
		wblist = info->wblist;
	else if (info->whitelisting)
		wblist = &data->config.whitelist_write;
	else
		wblist = &data->config.blacklist_write;

	if (info->whitelisting) {
		if (box_match_path(abspath, wblist, NULL)) {
			r = 0;
			info("check_path path:'%s' matches a whitelist pattern,"
					" access granted",
					abspath);
			goto out;
		}
	}
	else if (!box_match_path(abspath, wblist, NULL)) {
		/* Path does not match one of the blacklisted path patterns.
		 * Allow access.
		 */
		r = 0;
		info("check_path: path:'%s' does not match any blacklist pattern,"
				" access granted",
				abspath);
		goto out;
	}

	errno = info->deny_errno ? info->deny_errno : EPERM;

	if (info->safe && !sydbox->config.violation_raise_safe) {
		r = deny(current);
		goto out;
	}

	if (info->create == MUST_CREATE) {
		/* The system call *must* create the file */
		int sr;
		struct stat buf;

		sr = info->resolve ? stat(abspath, &buf) : lstat(abspath, &buf);
		if (sr == 0) {
			/* Yet the file exists... */
			info("check_path: sys:%s() must create existant path:'%s'",
					name, abspath);
			info("check_path: deny access with EEXIST");
			errno = EEXIST;
			if (!sydbox->config.violation_raise_safe) {
				r = deny(current);
				goto out;
			}
		}
		else
			errno = info->deny_errno ? info->deny_errno : EPERM;
	}

	r = deny(current);

	if (!box_match_path(abspath, info->filter ? info->filter : &sydbox->config.filter_write, NULL)) {
		if (info->at)
			box_report_violation_path_at(current, name, info->arg_index, path, prefix);
		else
			box_report_violation_path(current, name, info->arg_index, path);
	}

out:
	if (prefix)
		free(prefix);
	if (path)
		free(path);
	if (abspath)
		free(abspath);

	return r;
}

int box_check_socket(struct pink_easy_process *current, const char *name, sys_info_t *info)
{
	int r;
	char *abspath;
	struct snode *node;
	sock_match_t *m;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	struct pink_sockaddr *psa;

	assert(current);
	assert(info);

	debug("check_socket: %s[%lu:%u] sys:%s() arg_index:%u decode:%s",
			data->comm, (unsigned long)tid, abi, name,
			info->arg_index,
			info->decode_socketcall ? "true" : "false");
	debug("check_socket: safe:%s deny-errno:%s whitelisting:%s",
			info->safe ? "true" : "false",
			errno_to_string(info->deny_errno),
			info->whitelisting ? "true" : "false");

	r = 0;
	abspath = NULL;
	psa = xmalloc(sizeof(struct pink_sockaddr));

	if (!pink_read_socket_address(tid, abi, &data->regs,
				info->decode_socketcall,
				info->arg_index, info->fd, psa)) {
		if (errno != ESRCH) {
			warning("check_socket: read sockaddr at index:%d failed (errno:%d %s)",
					info->arg_index, errno, strerror(errno));
			r = panic(current);
			goto out;
		}
		info("check_socket: read sockaddr at index:%d failed (errno:%d %s)",
				info->arg_index, errno, strerror(errno));
		info("check_socket: drop process %s[%lu:%u]",
				data->comm,
				(unsigned long)tid, abi);
		r = PINK_EASY_CFLAG_DROP;
		goto out;
	}

	/* Check for supported socket family. */
	switch (psa->family) {
	case AF_UNIX:
	case AF_INET:
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
#endif
		break;
	default:
		if (sydbox->config.whitelist_unsupported_socket_families) {
			debug("check_socket: whitelist unsupported sockfamily:%d", psa->family);
			goto out;
		}
		errno = EAFNOSUPPORT;
		r = deny(current);
		goto report;
	}

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket, resolve the path. */
		if ((r = box_resolve_path(psa->u.sa_un.sun_path, data->cwd,
						tid, 1,
						info->resolve,
						&abspath)) < 0) {
			info("check_socket: resolve path:'%s' for sys:%s() failed (errno:%d %s)",
					psa->u.sa_un.sun_path, name, -r, strerror(-r));
			errno = -r;
			r = deny(current);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto out;
		}

		SLIST_FOREACH(node, info->wblist, up) {
			m = node->data;
			if (m->family == AF_UNIX && !m->match.sa_un.abstract) {
				if (info->whitelisting) {
					if (wildmatch_syd(m->match.sa_un.path, abspath))
						goto out;
				}
				else if (!wildmatch_syd(m->match.sa_un.path, abspath))
					goto out;
			}
		}

		errno = info->deny_errno;
		r = deny(current);
		goto filter;
	}

	SLIST_FOREACH(node, info->wblist, up) {
		if (info->whitelisting) {
			if (sock_match(node->data, psa))
				goto out;
		}
		else if (!sock_match(node->data, psa))
			goto out;
	}

	errno = info->deny_errno;
	r = deny(current);

filter:
	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		SLIST_FOREACH(node, info->filter, up) {
			m = node->data;
			if (m->family == AF_UNIX
					&& !m->match.sa_un.abstract
					&& wildmatch_syd(m->match.sa_un.path, abspath))
				goto out;
		}
	}
	else {
		SLIST_FOREACH(node, info->filter, up) {
			if (sock_match(node->data, psa))
				goto out;
		}
	}

report:
	box_report_violation_sock(current, info, name, psa);

out:
	if (!r) {
		if (info->abspath)
			*info->abspath = abspath;
		else if (abspath)
			free(abspath);

		if (info->addr)
			*info->addr = psa;
		else
			free(psa);
	}
	else {
		if (abspath)
			free(abspath);
		free(psa);
	}

	return r;
}
