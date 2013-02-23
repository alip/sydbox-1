/*
 * sydbox/sandbox.c
 *
 * Sandboxing utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pinktrace/pink.h>
#include "macro.h"
#include "canonicalize.h"
#include "file.h"
#include "log.h"
#include "path.h"
#include "pathdecode.h"
#include "pathmatch.h"
#include "sockmatch.h"
#include "proc.h"
#include "strtable.h"
#include "util.h"

static void box_report_violation_path(syd_proc_t *current,
				      unsigned arg_index,
				      const char *path)
{
	const char *name = current->sysname;

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

static void box_report_violation_path_at(syd_proc_t *current,
					 unsigned arg_index,
					 const char *path,
					 const char *prefix)
{
	const char *name = current->sysname;

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

static void box_report_violation_sock(syd_proc_t *current,
				      const sysinfo_t *info,
				      const struct pink_sockaddr *paddr)
{
	char ip[64];
	const char *f;
	bool abstract;
	const char *name = current->sysname;

	switch (paddr->family) {
	case AF_UNIX:
		abstract = path_abstract(paddr->u.sa_un.sun_path);
		violation(current, "%s(%d, %s:%s)",
			  name,
			  info->ret_fd ? *info->ret_fd : -1,
			  abstract ? "unix-abstract" : "unix",
			  abstract ? paddr->u.sa_un.sun_path
				   : paddr->u.sa_un.sun_path + 1);
		break;
	case AF_INET:
		inet_ntop(AF_INET, &paddr->u.sa_in.sin_addr, ip, sizeof(ip));
		violation(current, "%s(%d, inet:%s@%d)", name,
			  info->ret_fd ? *info->ret_fd : -1,
			  ip, ntohs(paddr->u.sa_in.sin_port));
		break;
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
		inet_ntop(AF_INET6, &paddr->u.sa6.sin6_addr, ip, sizeof(ip));
		violation(current, "%s(%d, inet6:%s@%d)", name,
			  info->ret_fd ? *info->ret_fd : -1,
			  ip, ntohs(paddr->u.sa6.sin6_port));
		break;
#endif
	default:
		f = address_family_to_string(paddr->family);
		violation(current, "%s(-1, ?:%s)", name, f ? f : "AF_???");
		break;
	}
}

static int box_resolve_path_helper(const char *abspath, pid_t tid,
				   can_mode_t can_mode, char **res)
{
	int r;
	char *p;

	p = NULL;
	/* Special case for /proc/self.
	 * This symbolic link resolves to /proc/$tid, if we let
	 * canonicalize_filename_mode() resolve this, we'll get a different result.
	 */
	if (startswith(abspath, "/proc/self")) {
		const char *tail = abspath + STRLEN_LITERAL("/proc/self");
		if (!*tail || *tail == '/') {
			if (asprintf(&p, "/proc/%u%s", tid, tail) < 0)
				return -errno;
		}
		log_check("proc_self(%u) = `/proc/%u'", tid, tid);
	}

	r = canonicalize_filename_mode(p ? p : abspath, can_mode, res);
	if (r == 0)
		log_check("canonicalize(`%s') = `%s'", p ? p : abspath, *res);
	else
		log_check("canonicalize(`%s') = NULL can_mode=%d errno:%d|%s| (%s)",
			  p ? p : abspath, can_mode,
			  -r, errno_to_string(-r), strerror(-r));

	if (p)
		free(p);

	return r;
}

int box_resolve_path(const char *path, const char *prefix, pid_t tid,
		     can_mode_t can_mode, char **res)
{
	int r;
	char *abspath;

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

	r = box_resolve_path_helper(abspath, tid, can_mode, res);
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

static int box_match_socket_(const slist_t *patterns, const void *psa)
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

static int box_check_ftype(const char *path, sysinfo_t *info)
{
	bool call_lstat;
	int deny_errno, stat_ret;
	int can_flags = info->can_mode & ~CAN_MODE_MASK;
	struct stat buf;

	assert(info);

	if (!info->syd_mode && !info->ret_mode)
		return 0;

	call_lstat = !!(can_flags & CAN_NOLINKS);
	stat_ret = call_lstat ? lstat(path, &buf) : stat(path, &buf);

	if (stat_ret < 0)
		return 0; /* stat() failed, TODO: are we fine returning 0? */

	if (info->ret_mode)
		*info->ret_mode = buf.st_mode;

	if (!info->syd_mode)
		return 0;

	deny_errno = 0;

	/*
	 * Note: order may matter, e.g.:
	 *	rmdir($loop-symlink) -> -ELOOP (not ENOTDIR)
	 */
	if (info->syd_mode & SYD_STAT_NOEXIST) {
		/*
		 * stat() has *not* failed which means file exists.
		 */
		deny_errno = EEXIST;
	} else if (info->syd_mode & SYD_STAT_NOFOLLOW && S_ISLNK(buf.st_mode)) {
		/*
		 * System call requires a non-symlink.
		 */
		deny_errno = ELOOP;
	} else if (info->syd_mode & SYD_STAT_ISDIR && !S_ISDIR(buf.st_mode)) {
		/*
		 * System call requires a directory.
		 */
		deny_errno = ENOTDIR;
	} else if (info->syd_mode & SYD_STAT_NOTDIR && S_ISDIR(buf.st_mode)) {
		/*
		 * System call requires a non-directory.
		 */
		deny_errno = EISDIR;
	} else if (info->syd_mode & SYD_STAT_EMPTYDIR) {
		if (!S_ISDIR(buf.st_mode))
			deny_errno = ENOTDIR;
		else if (!empty_dir(path))
			deny_errno = ENOTEMPTY;
	}

	if (deny_errno != 0)
		log_access("check_filetype(`%s') = %d|%s| (%s)",
			   path, deny_errno, errno_to_string(deny_errno),
			   strerror(deny_errno));
	return deny_errno;
}

int box_check_path(syd_proc_t *current, sysinfo_t *info)
{
	bool badfd;
	int r, deny_errno, stat_errno;
	pid_t pid;
	char *prefix, *path, *abspath;

	assert(current);
	assert(info);

	pid = GET_PID(current);
	prefix = path = abspath = NULL;
	deny_errno = info->deny_errno ? info->deny_errno : EPERM;

	log_check("arg_index=%u cwd:`%s'", info->arg_index, current->cwd);
	log_check("at_func=%s null_ok=%s can_mode=%d syd_mode=0x%x",
		  info->at_func ? "yes" : "no",
		  info->null_ok ? "yes" : "no",
		  info->can_mode, info->syd_mode);
	log_check("safe=%s deny-errno=%d|%s| access_mode=%s",
		  strbool(info->safe),
		  deny_errno, errno_to_string(deny_errno),
		  sys_access_mode_to_string(info->access_mode));

	/* Step 1: resolve file descriptor for `at' suffixed functions */
	badfd = false;
	if (info->at_func) {
		r = path_prefix(current, info->arg_index - 1, &prefix);
		if (r == -ESRCH) {
			return -ESRCH;
		} else if (r == -EBADF) {
			/* Using a bad directory for absolute paths is fine!
			 * System call will be denied after path_decode()
			 */
			badfd = true;
		} else if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			return r;
		}
	}

	/* Step 2: read path */
	if ((r = path_decode(current, info->arg_index, &path)) < 0) {
		/*
		 * For EFAULT we assume path argument is NULL.
		 * For some `at' suffixed functions, NULL as path
		 * argument may be OK.
		 */
		if (!(r == -EFAULT && info->at_func && info->null_ok)) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			goto out;
		} else if (r == -ESRCH) {
			goto out;
		}
	} else { /* r == 0 */
		if (badfd && !path_is_absolute(path)) {
			/* Bad directory for non-absolute path! */
			r = deny(current, -EBADF);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			goto out;
		}
	}

	/* Step 3: resolve path */
	if ((r = box_resolve_path(path, prefix ? prefix : current->cwd,
				  pid, info->can_mode, &abspath)) < 0) {
		err_access(-r, "resolve_path(`%s', `%s')",
			   prefix ? prefix : current->cwd, abspath);
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s()", current->sysname);
		goto out;
	}

	/* Step 4: Check for access */
	enum sys_access_mode access_mode;
	slist_t *access_lists[2], *access_filter;

	if (info->access_mode != ACCESS_0)
		access_mode = info->access_mode;
	else if (sandbox_write_deny(current))
		access_mode = ACCESS_WHITELIST;
	else
		access_mode = ACCESS_BLACKLIST;

	if (info->access_list)
		access_lists[0] = info->access_list;
	else if (access_mode == ACCESS_WHITELIST)
		access_lists[0] = &current->config.whitelist_write;
	else /* if (info->access_mode == ACCESS_BLACKLIST) */
		access_lists[0] = &current->config.blacklist_write;
	access_lists[1] = info->access_list_global;

	if (box_check_access(access_mode, box_match_path_,
			     access_lists, 2, abspath)) {
		log_access("allowing access to `%s'", abspath);
		r = 0;
		goto out;
	} else {
		log_access("denying access to `%s'", abspath);
	}

	if (info->safe && !sydbox->config.violation_raise_safe) {
		log_access("ignoring safe system call");
		r = deny(current, deny_errno);
		goto out;
	}

	/* Step 5: stat() if required */
	if ((stat_errno = box_check_ftype(abspath, info)) != 0) {
		deny_errno = stat_errno;
		if (!sydbox->config.violation_raise_safe) {
			log_access("ignoring safe system call");
			r = deny(current, deny_errno);
			goto out;
		}
	}

	/* Step 6: report violation */
	r = deny(current, deny_errno);

	if (info->access_filter)
		access_filter = info->access_filter;
	else
		access_filter = &sydbox->config.filter_write;

	if (!box_match_path(access_filter, abspath, NULL)) {
		if (info->at_func)
			box_report_violation_path_at(current, info->arg_index,
						     path, prefix);
		else
			box_report_violation_path(current, info->arg_index, path);
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

int box_check_socket(syd_proc_t *current, sysinfo_t *info)
{
	int r;
	char *abspath;
	pid_t pid;
	struct pink_sockaddr *psa;

	assert(current);
	assert(info);
	assert(info->deny_errno != 0);
	assert(info->access_mode != ACCESS_0);
	assert(info->access_list);
	assert(info->access_filter);

	log_check("arg_index=%u decode=%s", info->arg_index,
		  strbool(info->decode_socketcall));
	log_check("safe=%s deny-errno=%d|%s| access_mode=%s",
		  strbool(info->safe),
		  info->deny_errno, errno_to_string(info->deny_errno),
		  sys_access_mode_to_string(info->access_mode));

	r = 0;
	pid = GET_PID(current);
	abspath = NULL;
	psa = xmalloc(sizeof(struct pink_sockaddr));

	if ((r = syd_read_socket_address(current, info->decode_socketcall,
					 info->arg_index, info->ret_fd,
					 psa)) < 0)
		goto out;

	/* check for supported socket family. */
	switch (psa->family) {
	case AF_UNIX:
	case AF_INET:
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
#endif
		break;
	default:
		if (sydbox->config.whitelist_unsupported_socket_families) {
			log_access("allowing unsupported socket family %d|%s|",
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

	if (psa->family == AF_UNIX && !path_abstract(psa->u.sa_un.sun_path)) {
		/* Non-abstract UNIX socket, resolve the path. */
		r = box_resolve_path(psa->u.sa_un.sun_path,
				     current->cwd, pid,
				     info->can_mode, &abspath);
		if (r < 0) {
			err_access(-r, "resolve_path(`%s', `%s')",
				   current->cwd, abspath);
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
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
			log_access("access to sockaddr `%p' granted", (void *)psa);
			r = 0;
			goto out;
		} else {
			log_access("access to sockaddr `%p' denied", (void *)psa);
		}
	}

	r = deny(current, info->deny_errno);

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		if (box_match_path_saun(info->access_filter, abspath, NULL)) {
			log_access("sun_path=`%s' matches a filter pattern, violation filtered",
				   abspath);
			goto out;
		}
	} else {
		if (box_match_socket(info->access_filter, psa, NULL)) {
			log_access("sockaddr=%p matches a filter pattern, violation filtered",
				   (void *)psa);
			goto out;
		}
	}

report:
	box_report_violation_sock(current, info, psa);

out:
	if (r == 0) {
		/* Access granted. */
		if (info->ret_abspath)
			*info->ret_abspath = abspath;
		else if (abspath)
			free(abspath);

		if (info->ret_addr)
			*info->ret_addr = psa;
		else
			free(psa);
	} else {
		free(psa);
		if (abspath)
			free(abspath);
		if (info->ret_abspath)
			*info->ret_abspath = NULL;
		if (info->ret_addr)
			*info->ret_addr = NULL;
	}

	return r;
}
