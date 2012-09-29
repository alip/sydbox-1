/*
 * sydbox/sydbox-box.c
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

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
#include "pathdecode.h"
#include "pathmatch.h"
#include "sockmatch.h"
#include "proc.h"
#include "strtable.h"
#include "util.h"
#include "sys-check.h"

static inline void box_report_violation_path(struct pink_easy_process *current,
					     const char *name,
					     unsigned arg_index,
					     const char *path)
{
	switch (arg_index) {
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
						const char *name,
						unsigned arg_index,
						const char *path,
						const char *prefix)
{
	switch (arg_index) {
	case 1:
		violation(current, "%s(`%s', prefix=`%s')",
			  name, path, prefix);
		break;
	case 2:
		violation(current, "%s(?, `%s', prefix=`%s')",
			  name, path, prefix);
		break;
	case 3:
		violation(current, "%s(?, ?, '%s', prefix=`%s')",
			  name, path, prefix);
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
				*paddr->u.sa_un.sun_path
					? "unix"
					: "unix-abstract",
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
				   can_mode_t can_mode, char **res)
{
	int r;
	char *p;

	p = NULL;
	/* Special case for /proc/self.
	 * This symbolic link resolves to /proc/$pid, if we let
	 * canonicalize_filename_mode() resolve this, we'll get a different result.
	 */
	if (startswith(abspath, "/proc/self")) {
		const char *tail = abspath + STRLEN_LITERAL("/proc/self");
		if (!*tail || *tail == '/') {
			if (asprintf(&p, "/proc/%lu%s",
				     (unsigned long)pid,
				     tail) < 0)
				return -errno;
		}
		log_check("/proc/self is `/proc/%lu'", (unsigned long)pid);
	}

	r = canonicalize_filename_mode(p ? p : abspath, can_mode, res);
	if (r == 0)
		log_check("canonicalize `%s' to `%s'",
			  p ? p : abspath, *res);
	else
		log_check("canonicalize `%s' failed (errno:%d %s)",
			  p ? p : abspath, -r, strerror(-r));

	if (p)
		free(p);

	return r;
}

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		     can_mode_t can_mode, char **res)
{
	int r;
	char *abspath;

	log_check("pid=%lu can_mode=%d", (unsigned long)pid, can_mode);
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

	r = box_resolve_path_helper(abspath, pid, can_mode, res);
	free(abspath);
	return r;
}

int box_match_path(const slist_t *patterns, const char *path,
		   const char **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (pathmatch(node->data, path)) {
			if (match)
				*match = node->data;
			return 1;
		}
	}

	return 0;
}

static int box_match_path_(const slist_t *patterns, const void *path)
{
	return box_match_path(patterns, path, NULL);
}

static int box_match_path_saun(const slist_t *patterns, const char *sun_path,
			       const char **match)
{
	struct snode *node;
	struct sockmatch *m;

	SLIST_FOREACH(node, patterns, up) {
		m = node->data;
		if (m->family == AF_UNIX && !m->addr.sa_un.abstract) {
			if (pathmatch(m->addr.sa_un.path, sun_path)) {
				if (match)
					*match = node->data;
				return 1;
			}
		}
	}

	return 0;
}

static int box_match_path_saun_(const slist_t *patterns, const void *sun_path)
{
	return box_match_path_saun(patterns, sun_path, NULL);
}

static int box_match_socket(const slist_t *patterns,
			    const struct pink_sockaddr *psa,
			    struct sockmatch **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (sockmatch(node->data, psa)) {
			if (match)
				*match = node->data;
			return 1;
		}
	}

	return 0;
}

static int box_match_socket_(const slist_t *patterns,
			     const void *psa)
{
	return box_match_socket(patterns, psa, NULL);
}

static int box_check_access(enum sys_access_mode mode,
			    int (*match_func)(const slist_t *patterns,
					      const void *needle),
			    slist_t **pattern_list,
			    size_t pattern_list_len,
			    void *needle)
{
	unsigned i;

	assert(match_func);

	switch (mode) {
	case ACCESS_WHITELIST:
		for (i = 0; i < pattern_list_len; i++) {
			if (pattern_list[i] &&
			    match_func(pattern_list[i], needle))
				return 1;
		}
		return 0;
	case ACCESS_BLACKLIST:
		for (i = 0; i < pattern_list_len; i++) {
			if (pattern_list[i] &&
			    match_func(pattern_list[i], needle))
				return 0;
		}
		return 1;
	default:
		assert_not_reached();
	}
}

int box_check_path(struct pink_easy_process *current, const char *name,
		   sysinfo_t *info)
{
	bool badfd;
	int r, deny_errno;
	char *prefix, *path, *abspath;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	assert(current);
	assert(info);

	prefix = path = abspath = NULL;
	deny_errno = info->deny_errno ? info->deny_errno : EPERM;

	log_check("%s[%lu:%u] sys=%s arg_index=%u cwd:`%s'",
			data->comm, (unsigned long)tid, abi, name,
			info->arg_index, data->cwd);
	log_check("at_func=%s null_ok=%s can_mode=%d syd_mode=%#x",
			info->at_func ? "yes" : "no",
			info->null_ok ? "yes" : "no",
			info->can_mode, info->syd_mode);
	log_check("safe=%s deny-errno=%s access_mode=%s",
			info->safe ? "yes" : "no",
			errno_to_string(deny_errno),
			sys_access_mode_to_string(info->access_mode));

	/* Step 1: resolve file descriptor for `at' suffixed functions */
	badfd = false;
	if (info->at_func) {
		r = path_prefix(current, info->arg_index - 1, &prefix);
		if (r == -EBADF) {
			/* Using a bad directory for absolute paths is fine!
			 * System call will be denied after path_decode()
			 */
			badfd = true;
		} else if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			return r;
		} else if (r > 0) { /* PINK_EASY_CFLAG */
			return r;
		}
	}

	/* Step 2: read path */
	r = path_decode(current, info->arg_index, &path);
	if (r < 0) {
		/* For EFAULT we assume path argument is NULL.
		 * For some `at' suffixed functions, NULL as path
		 * argument may be OK.
		 */
		if (!(r == -EFAULT && info->at_func && info->null_ok)) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto out;
		}
	} else if (r > 0) { /* PINK_EASY_CFLAG */
		goto out;
	} else { /* r == 0 */
		if (badfd && !path_is_absolute(path)) {
			/* Bad directory for non-absolute path! */
			r = deny(current, -EBADF);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto out;
		}
	}

	/* Step 3: resolve path */
	r = box_resolve_path(path, prefix ? prefix : data->cwd, tid,
			     info->can_mode, &abspath);
	if (r < 0) {
		log_access("resolve path=`%s' for sys=%s() failed"
			   " (errno=%d %s)",
			   path, name, -r, strerror(-r));
		log_access("deny access with errno=%s", errno_to_string(-r));
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto out;
	}

	/* Step 4: Check for access */
	enum sys_access_mode access_mode;
	slist_t *access_lists[2], *access_filter;

	if (info->access_mode != ACCESS_0)
		access_mode = info->access_mode;
	else if (sandbox_write_deny(data))
		access_mode = ACCESS_WHITELIST;
	else
		access_mode = ACCESS_BLACKLIST;

	if (info->access_list)
		access_lists[0] = info->access_list;
	else if (access_mode == ACCESS_WHITELIST)
		access_lists[0] = &data->config.whitelist_write;
	else /* if (info->access_mode == ACCESS_BLACKLIST) */
		access_lists[0] = &data->config.blacklist_write;
	access_lists[1] = info->access_list_global;

	if (box_check_access(access_mode, box_match_path_,
			     access_lists, 2, abspath)) {
		log_access("access to path `%s' granted", abspath);
		r = 0;
		goto out;
	} else {
		log_access("access to path `%s' denied", abspath);
	}

	if (info->safe && !sydbox->config.violation_raise_safe) {
		log_access("sys=%s is safe, access violation filtered", name);
		r = deny(current, deny_errno);
		goto out;
	}

	/* Step 5: stat() if required */
	if (info->syd_mode) {
		int stat_ret, stat_errno = 0;
		int can_flags = info->can_mode & ~CAN_MODE_MASK;
		struct stat buf;

		if (info->syd_mode & SYD_IFNOLNK || can_flags & CAN_NOLINKS)
			stat_ret = lstat(abspath, &buf);
		else
			stat_ret = stat(abspath, &buf);

		if (stat_ret == 0) {
			if (info->syd_mode & SYD_IFDIR &&
			    !S_ISDIR(buf.st_mode)) {
				/* The file must be a directory yet it isn't!
				 * Deny with -ENOTDIR
				 */
				log_access("sys=%s requires a directory", name);
				stat_errno = ENOTDIR;
			} else if (info->syd_mode & SYD_IFNOLNK &&
				 S_ISLNK(buf.st_mode)) {
				/* The file must not be symlink yet it is!
				 * Deny with -ELOOP
				 */
				log_access("sys=%s requires a non-link", name);
				stat_errno = ELOOP;
			} else if (info->syd_mode & SYD_IFNONE) {
				/* The file can't exist yet it does!
				 * Deny with -EEXIST
				 */
				log_access("sys=%s must create path", name);
				stat_errno = EEXIST;
			}

			if (stat_errno != 0) {
				log_access("access for path `%s'"
					   " denied with errno=%s",
					   abspath,
					   errno_to_string(stat_errno));
				deny_errno = stat_errno;
				if (!sydbox->config.violation_raise_safe) {
					log_access("sys=%s is safe,"
						   " access violation filtered",
						   name);
					r = deny(current, deny_errno);
					goto out;
				}
			}
		}
	}

	r = deny(current, deny_errno);

	if (info->access_filter)
		access_filter = info->access_filter;
	else
		access_filter = &sydbox->config.filter_write;

	if (!box_match_path(access_filter, abspath, NULL)) {
		if (info->at_func)
			box_report_violation_path_at(current, name,
						     info->arg_index,
						     path, prefix);
		else
			box_report_violation_path(current, name,
						  info->arg_index,
						  path);
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

int box_check_socket(struct pink_easy_process *current, const char *name,
		     sysinfo_t *info)
{
	int r;
	char *abspath;
	struct snode *node;
	struct sockmatch *m;
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

	log_check("%s[%lu:%u] sys=%s arg_index=%u decode=%s",
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
			log_warning("read sockaddr at index=%d failed"
				    " (errno=%d %s)",
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
			log_access("unsupported sockfamily:%d/%s"
				   ", access granted",
				   psa->family,
				   address_family_to_string(psa->family));
			goto out;
		}
		r = deny(current, EAFNOSUPPORT);
		goto report;
	}

	slist_t *access_lists[2];
	access_lists[0] = info->access_list;
	access_lists[1] = info->access_list_global;

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket, resolve the path. */
		r = box_resolve_path(psa->u.sa_un.sun_path,
				     data->cwd, tid,
				     info->can_mode, &abspath);
		if (r < 0) {
			log_access("resolve path=`%s' for sys=%s failed"
				   " (errno=%d %s)",
				   psa->u.sa_un.sun_path,
				   name, -r, strerror(-r));
			log_access("access denied with errno=%s",
				   errno_to_string(-r));
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto out;
		}

		if (box_check_access(info->access_mode, box_match_path_saun_,
				     access_lists, 2, abspath)) {
			log_access("access to sun_path `%s' granted", abspath);
			r = 0;
			goto out;
		} else {
			log_access("access to sun_path `%s' denied", abspath);
		}
	} else {
		if (box_check_access(info->access_mode, box_match_socket_,
				     access_lists, 2, psa)) {
			log_access("access to sockaddr `%p' granted", psa);
			r = 0;
			goto out;
		} else {
			log_access("access to sockaddr `%p' denied", psa);
		}
	}

	r = deny(current, info->deny_errno);

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		if (box_match_path_saun(info->access_filter, abspath, NULL)) {
			log_access("sun_path=`%s' matches a filter pattern,"
				   " access violation filtered",
				   abspath);
			goto out;
		}
	} else {
		if (box_match_socket(info->access_filter, psa, NULL)) {
			log_access("sockaddr=%p matches a filter pattern,"
				   " access violation filtered",
				   psa);
			goto out;
		}
	}

report:
	box_report_violation_sock(current, info, name, psa);

out:
	if (r == 0) {
		/* Access granted. */
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
