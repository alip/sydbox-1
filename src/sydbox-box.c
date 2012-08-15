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
#include "log.h"
#include "path.h"
#include "proc.h"
#include "strtable.h"
#include "util.h"

static inline void box_report_violation_path(struct pink_easy_process *current,
		const char *name, unsigned ind, const char *path)
{
	switch (ind) {
	case 0:
		violation(current, "%s(`%s')", name, path);
		break;
	case 1:
		violation(current, "%s(?, `%s')", name, path);
		break;
	case 2:
		violation(current, "%s(?, ?, `%s')", name, path);
		break;
	case 3:
		violation(current, "%s(?, ?, ?, `%s')", name, path);
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
		violation(current, "%s(`%s', prefix=`%s')", name, path, prefix);
		break;
	case 2:
		violation(current, "%s(?, `%s', prefix=`%s')", name, path, prefix);
		break;
	case 3:
		violation(current, "%s(?, ?, '%s', prefix=`%s')", name, path, prefix);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static void box_report_violation_sock(struct pink_easy_process *current,
		const sysinfo_t *info, const char *name,
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
		enum file_exist_mode file_mode, bool no_resolve,
		char **res)
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
		log_check("/proc/self is `/proc/%lu'", (unsigned long)pid);
	}

	can_mode = (file_mode == FILE_MUST_EXIST) ? CAN_EXISTING : CAN_ALL_BUT_LAST;
	if (no_resolve)
		can_mode |= CAN_NOLINKS;
	r = canonicalize_filename_mode(p ? p : abspath, can_mode, res);

	if (r == 0)
		log_check("canonicalize `%s' to `%s'", p ? p : abspath, *res);
	else
		log_check("canonicalize `%s' failed", p ? p : abspath);

	if (p)
		free(p);

	return r;
}

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		enum file_exist_mode file_mode, bool no_resolve,
		char **res)
{
	int r;
	char *abspath;

	log_check("pid=%lu file_mode=%s resolve=%s",
			(unsigned long)pid,
			file_exist_mode_to_string(file_mode),
			no_resolve ? "no" : "yes");
	log_check("path=`%s' prefix=`%s'", path, prefix);

	if (path == NULL && prefix == NULL)
		return -EINVAL;
	if (path == NULL)
		abspath = xstrdup(prefix);
	else if (prefix == NULL)
		abspath = xstrdup(path);
	else
		abspath = path_make_absolute(path, prefix);
	if (!abspath)
		return -errno;

	r = box_resolve_path_helper(abspath, pid, file_mode, no_resolve, res);
	free(abspath);
	return r;
}

int box_match_path(const char *path, const slist_t *patterns, const char **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (wildmatch_sydbox(node->data, path)) {
			if (match)
				*match = node->data;
			return 1;
		}
	}

	return 0;
}

static int box_match_path_saun(const char *path, const slist_t *patterns, const char **match)
{
	struct snode *node;
	sock_match_t *m;

	SLIST_FOREACH(node, patterns, up) {
		m = node->data;
		if (m->family == AF_UNIX && !m->match.sa_un.abstract) {
			if (wildmatch_sydbox(m->match.sa_un.path, path)) {
				if (match)
					*match = node->data;
				return 1;
			}
		}
	}

	return 0;
}

static int box_match_socket(const struct pink_sockaddr *psa, const slist_t *patterns, sock_match_t **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (sock_match(node->data, psa)) {
			if (match)
				*match = node->data;
			return 1;
		}
	}

	return 0;
}

int box_check_path(struct pink_easy_process *current, const char *name, sysinfo_t *info)
{
	int r, deny_errno;
	char *prefix, *path, *abspath;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	slist_t *access_list;

	assert(current);
	assert(info);

	prefix = path = abspath = NULL;
	deny_errno = info->deny_errno ? info->deny_errno : EPERM;
	if (info->access_mode == ACCESS_0)
		info->access_mode = sandbox_write_deny(data) ? ACCESS_WHITELIST : ACCESS_BLACKLIST;

	log_check("%s[%lu:%u] sys=%s() arg_index=%u cwd:`%s'",
			data->comm, (unsigned long)tid, abi, name,
			info->arg_index, data->cwd);
	log_check("at_func=%s null_ok=%s resolve=%s create=%s",
			info->at_func ? "yes" : "no",
			info->null_ok ? "yes" : "no",
			info->no_resolve ? "no" : "yes",
			file_exist_mode_to_string(info->file_mode));
	log_check("safe=%s deny-errno=%s access_mode=%s",
			info->safe ? "yes" : "no",
			errno_to_string(deny_errno),
			sys_access_mode_to_string(info->access_mode));

	if (info->at_func && (r = path_prefix(current, info->arg_index-1, &prefix))) {
		if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
		}
		return r;
	}

	r = path_decode(current, info->arg_index, &path);
	if (r < 0 && !(info->at_func && info->null_ok && prefix && r == -EFAULT)) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto out;
	} else if (r > 0 /* PINK_EASY_CFLAG */) {
		goto out;
	}

	if ((r = box_resolve_path(path, prefix ? prefix : data->cwd,
					tid,
					info->file_mode,
					info->no_resolve, &abspath)) < 0) {
		log_access("resolve path=`%s' for sys=%s() failed (errno=%d %s)",
				path, name, -r, strerror(-r));
		log_access("deny access with errno=%s", errno_to_string(-r));
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto out;
	}

	if (info->access_list)
		access_list = info->access_list;
	else if (info->access_mode == ACCESS_WHITELIST)
		access_list = &data->config.whitelist_write;
	else /* if (info->access_mode == ACCESS_BLACKLIST) */
		access_list = &data->config.blacklist_write;

	if (info->access_mode == ACCESS_WHITELIST) {
		if (box_match_path(abspath, access_list, NULL)) {
			log_access("path=`%s' matches a whitelist pattern,"
					" access granted", abspath);
			r = 0;
			goto out;
		} else {
			log_access("path=`%s' does not match a whitelist pattern,"
					" access denied", abspath);
		}
	} else /* if (info->access_mode == ACCESS_BLACKLIST) */ {
		if (!box_match_path(abspath, access_list, NULL)) {
			log_access("path=`%s' does not match any blacklist pattern,"
					" access granted", abspath);
			r = 0;
			goto out;
		} else {
			log_access("path=`%s' matches a blacklist pattern,"
					" access denied", abspath);
		}
	}

	if (info->safe && !sydbox->config.violation_raise_safe) {
		log_access("sys:%s() is safe, access violation filtered", name);
		r = deny(current, deny_errno);
		goto out;
	}

	if (info->file_mode == FILE_CANT_EXIST) {
		/* The system call *must* create the file */
		int sr;
		struct stat buf;

		sr = info->no_resolve ? lstat(abspath, &buf) : stat(abspath, &buf);
		if (sr == 0) {
			/* Yet the file exists... */
			log_access("sys=%s() must create existant path=`%s'", name, abspath);
			log_access("deny access with errno=EEXIST");
			deny_errno = EEXIST;
			if (!sydbox->config.violation_raise_safe) {
				log_access("sys:%s() is safe, access violation filtered", name);
				r = deny(current, deny_errno);
				goto out;
			}
		}
	}

	r = deny(current, deny_errno);

	if (!box_match_path(abspath, info->access_filter ? info->access_filter : &sydbox->config.filter_write, NULL)) {
		if (info->at_func)
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

int box_check_socket(struct pink_easy_process *current, const char *name, sysinfo_t *info)
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
	assert(info->deny_errno != 0);
	assert(info->access_mode != ACCESS_0);
	assert(info->access_list);
	assert(info->access_filter);

	log_check("%s[%lu:%u] sys=%s() arg_index=%u decode=%s",
			data->comm, (unsigned long)tid, abi, name,
			info->arg_index,
			info->decode_socketcall ? "yes" : "no");
	log_check("safe=%s deny-errno=%s access_mode=%s",
			info->safe ? "yes" : "no",
			errno_to_string(info->deny_errno),
			sys_access_mode_to_string(info->access_mode));

	r = 0;
	abspath = NULL;
	psa = xmalloc(sizeof(struct pink_sockaddr));

	if (!pink_read_socket_address(tid, abi, &data->regs,
				info->decode_socketcall,
				info->arg_index, info->fd, psa)) {
		if (errno != ESRCH) {
			log_warning("read sockaddr at index=%d failed (errno=%d %s)",
					info->arg_index, errno, strerror(errno));
			r = panic(current);
			goto out;
		}
		log_trace("read sockaddr at index=%d failed (errno=%d %s)",
				info->arg_index, errno, strerror(errno));
		log_trace("drop process  %s[%lu:%u]", data->comm,
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
			log_access("unsupported sockfamily:%d, access granted", psa->family);
			goto out;
		}
		r = deny(current, EAFNOSUPPORT);
		goto report;
	}

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket, resolve the path. */
		if ((r = box_resolve_path(psa->u.sa_un.sun_path, data->cwd,
						tid, FILE_MAY_EXIST,
						info->no_resolve,
						&abspath)) < 0) {
			log_access("resolve path=`%s' for sys=%s() failed (errno=%d %s)",
				psa->u.sa_un.sun_path,
				name, -r, strerror(-r));
			log_access("deny access with errno=%s", errno_to_string(-r));
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto out;
		}

		if (info->access_mode == ACCESS_WHITELIST) {
			if (box_match_path_saun(abspath, info->access_list, NULL)) {
				log_access("sun_path=`%s' matches a whitelist pattern,"
						" access granted",
						abspath);
				r = 0;
				goto out;
			} else {
				log_access("sun_path=`%s does not match a whitelist pattern,"
						" access denied",
						abspath);
			}
		} else if (info->access_mode == ACCESS_BLACKLIST) {
			if (!box_match_path(abspath, info->access_list, NULL)) {
				log_access("sun_path=`%s' does not match any blacklist pattern,"
						" access granted",
						abspath);
				r = 0;
				goto out;
			} else {
				log_access("sun_path=`%s matches a blacklist pattern,"
						" access denied",
						abspath);
			}
		}
	} else {
		if (info->access_mode == ACCESS_WHITELIST) {
			if (box_match_socket(psa, info->access_list, NULL)) {
				log_access("sockaddr=%p matches a whitelist pattern,"
						" access granted", psa);
				r = 0;
				goto out;
			}
		} else if (info->access_mode == ACCESS_BLACKLIST) {
			if (!box_match_socket(psa, info->access_list, NULL)) {
				log_access("sockaddr=%p does not match any blacklist pattern,"
						" access granted", psa);
				r = 0;
				goto out;
			} else {
				log_access("sockaddr=%p matches a blacklist pattern,"
						" access denied", psa);
			}
		}
	}

	r = deny(current, info->deny_errno);

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		if (box_match_path_saun(abspath, info->access_filter, NULL)) {
			log_access("sa_un=`%s' matches a filter pattern,"
					" access violation filtered", abspath);
			goto out;
		}
	} else {
		if (box_match_socket(psa, info->access_filter, NULL)) {
			log_access("sockaddr=%p matches a filter pattern,"
					" access violation filtered", psa);
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
	} else {
		if (abspath)
			free(abspath);
		free(psa);
	}

	return r;
}
