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

#ifndef SYS_CHECK_H
#define SYS_CHECK_H 1

#include <string.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>
#include "canonicalize.h"
#include "strtable.h"

enum sys_access_mode {
	ACCESS_0,
	ACCESS_WHITELIST,
	ACCESS_BLACKLIST
};
static const char *const sys_access_mode_table[] = {
	[ACCESS_0]         = "0",
	[ACCESS_WHITELIST] = "whitelist",
	[ACCESS_BLACKLIST] = "blacklist"
};
DEFINE_STRING_TABLE_LOOKUP(sys_access_mode, int)

typedef int (*sysfunc_t) (struct pink_easy_process *current, const char *name);

typedef struct {
	const char *name;
	sysfunc_t enter;
	sysfunc_t exit;
} sysentry_t;

typedef struct {
	unsigned arg_index; /* Argument index */

	bool at_func; /* at suffixed functions */

	bool null_ok; /* NULL argument doesn't cause -EFAULT (only valid for `at_func') */
	bool fail_if_exist; /* system call *must* create or it fails with -EEXIST */
	can_mode_t can_mode; /* canonicalize mode */

	bool decode_socketcall; /* decode socketcall() into subcall */

	bool safe; /* Safe system call, deny silently */
	int deny_errno;

	enum sys_access_mode access_mode; /* Access control mode (whitelist, blacklist) */
	slist_t *access_list; /* Access control list */
	slist_t *access_filter; /* Access filter list */

	/* Return data */
	long *fd;
	char **abspath;
	struct pink_sockaddr **addr;
} sysinfo_t;

static inline void init_sysinfo(sysinfo_t *info)
{
	memset(info, 0, sizeof(sysinfo_t));
}

extern int sys_chmod(struct pink_easy_process *current, const char *name);
extern int sys_fchmodat(struct pink_easy_process *current, const char *name);
extern int sys_chown(struct pink_easy_process *current, const char *name);
extern int sys_lchown(struct pink_easy_process *current, const char *name);
extern int sys_fchownat(struct pink_easy_process *current, const char *name);
extern int sys_open(struct pink_easy_process *current, const char *name);
extern int sys_openat(struct pink_easy_process *current, const char *name);
extern int sys_creat(struct pink_easy_process *current, const char *name);
extern int sys_close(struct pink_easy_process *current, const char *name);
extern int sys_mkdir(struct pink_easy_process *current, const char *name);
extern int sys_mkdirat(struct pink_easy_process *current, const char *name);
extern int sys_mknod(struct pink_easy_process *current, const char *name);
extern int sys_mknodat(struct pink_easy_process *current, const char *name);
extern int sys_rmdir(struct pink_easy_process *current, const char *name);
extern int sys_truncate(struct pink_easy_process *current, const char *name);
extern int sys_mount(struct pink_easy_process *current, const char *name);
extern int sys_umount(struct pink_easy_process *current, const char *name);
extern int sys_umount2(struct pink_easy_process *current, const char *name);
extern int sys_utime(struct pink_easy_process *current, const char *name);
extern int sys_utimes(struct pink_easy_process *current, const char *name);
extern int sys_utimensat(struct pink_easy_process *current, const char *name);
extern int sys_futimesat(struct pink_easy_process *current, const char *name);
extern int sys_unlink(struct pink_easy_process *current, const char *name);
extern int sys_unlinkat(struct pink_easy_process *current, const char *name);
extern int sys_link(struct pink_easy_process *current, const char *name);
extern int sys_linkat(struct pink_easy_process *current, const char *name);
extern int sys_rename(struct pink_easy_process *current, const char *name);
extern int sys_renameat(struct pink_easy_process *current, const char *name);
extern int sys_symlink(struct pink_easy_process *current, const char *name);
extern int sys_symlinkat(struct pink_easy_process *current, const char *name);
extern int sys_setxattr(struct pink_easy_process *current, const char *name);
extern int sys_lsetxattr(struct pink_easy_process *current, const char *name);
extern int sys_removexattr(struct pink_easy_process *current, const char *name);
extern int sys_lremovexattr(struct pink_easy_process *current, const char *name);

extern int sys_access(struct pink_easy_process *current, const char *name);
extern int sys_faccessat(struct pink_easy_process *current, const char *name);

extern int sys_dup(struct pink_easy_process *current, const char *name);
extern int sys_dup3(struct pink_easy_process *current, const char *name);
extern int sys_fcntl(struct pink_easy_process *current, const char *name);

extern int sys_execve(struct pink_easy_process *current, const char *name);
extern int sys_stat(struct pink_easy_process *current, const char *name);

extern int sys_socketcall(struct pink_easy_process *current, const char *name);
extern int sys_bind(struct pink_easy_process *current, const char *name);
extern int sys_connect(struct pink_easy_process *current, const char *name);
extern int sys_sendto(struct pink_easy_process *current, const char *name);
extern int sys_recvfrom(struct pink_easy_process *current, const char *name);
extern int sys_getsockname(struct pink_easy_process *current, const char *name);

extern int sysx_chdir(struct pink_easy_process *current, const char *name);
extern int sysx_close(struct pink_easy_process *current, const char *name);
extern int sysx_dup(struct pink_easy_process *current, const char *name);
extern int sysx_fcntl(struct pink_easy_process *current, const char *name);
extern int sysx_socketcall(struct pink_easy_process *current, const char *name);
extern int sysx_bind(struct pink_easy_process *current, const char *name);
extern int sysx_getsockname(struct pink_easy_process *current, const char *name);

#endif
