/*
 * sydbox/sys-check.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SYS_CHECK_H
#define SYS_CHECK_H 1

#include <string.h>
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>
#include "canonicalize.h"
#include "strtable.h"

typedef short syd_mode_t;
#define SYD_IFNONE	00001 /* file must not exist. */
#define SYD_IFDIR	00002 /* file must be a directory. */
#define SYD_IFNODIR	00004 /* file must not be a directory. */
#define SYD_IFNOLNK	00010 /* file must not be a symbolic link. */
#define SYD_IFBAREDIR	00020 /* file must be an empty directory. */

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
	long no; /* Used only if `name' is NULL.
		  * May be used to implement virtual system calls.
		  */
	sysfunc_t enter;
	sysfunc_t exit;
} sysentry_t;

typedef struct {
	/* Argument index */
	unsigned arg_index;

	/* `at' suffixed function */
	bool at_func;

	/* NULL argument does not cause -EFAULT (only valid for `at_func') */
	bool null_ok;
	/* Canonicalize mode */
	can_mode_t can_mode;
	/* Stat mode */
	syd_mode_t syd_mode;

	/* Decode socketcall() into subcall */
	bool decode_socketcall;

	/* Safe system call, deny silently (w/o raising access violation) */
	bool safe;
	/* Deny errno */
	int deny_errno;

	/* Access control mode (whitelist, blacklist) */
	enum sys_access_mode access_mode;
	/* Access control lists (per-process, global) */
	slist_t *access_list;
	slist_t *access_list_global;
	/* Access filter lists (only global) */
	slist_t *access_filter;

	/* Pointer to the data to be returned */
	bool *isdir;
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
extern int sys_getsockname(struct pink_easy_process *current, const char *name);

extern int sysx_chdir(struct pink_easy_process *current, const char *name);
extern int sysx_close(struct pink_easy_process *current, const char *name);
extern int sysx_dup(struct pink_easy_process *current, const char *name);
extern int sysx_fcntl(struct pink_easy_process *current, const char *name);
extern int sysx_socketcall(struct pink_easy_process *current, const char *name);
extern int sysx_bind(struct pink_easy_process *current, const char *name);
extern int sysx_getsockname(struct pink_easy_process *current, const char *name);

#endif
