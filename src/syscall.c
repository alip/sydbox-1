/*
 * sydbox/syscall.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <pinktrace/pink.h>
#include "macro.h"
#include "log.h"
#include "proc.h"
#ifdef WANT_SECCOMP
#include "seccomp.h"
#endif

/* Order matters! Put more frequent system calls above. */
static const sysentry_t syscall_entries[] = {
	{
		.name = "stat",
		.enter = sys_stat,
	},
	{
		.name = "lstat",
		.enter = sys_stat,
	},
	{
		.name = "stat64",
		.enter = sys_stat,
	},
	{
		.name = "lstat64",
		.enter = sys_stat,
	},

	{
		.name = "access",
		.enter = sys_access,
	},
	{
		.name = "faccessat",
		.enter = sys_faccessat,
	},

	{
		.name = "open",
		.enter = sys_open,
	},
	{
		.name = "openat",
		.enter = sys_openat,
	},
	{
		.name = "creat",
		.enter = sys_creat,
	},

	{
		.name = "dup",
		.enter = sys_dup,
		.exit = sysx_dup,
	},
	{
		.name = "dup2",
		.enter = sys_dup,
		.exit = sysx_dup,
	},
	{
		.name = "dup3",
		.enter = sys_dup,
		.exit = sysx_dup,
	},
	{
		.name = "fcntl",
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
	},
	{
		.name = "fcntl64",
		.enter = sys_fcntl,
		.exit = sysx_fcntl,
	},

	{
		.name = "chdir",
		.exit = sysx_chdir,
	},
	{
		.name = "fchdir",
		.exit = sysx_chdir,
	},

	{
		.name = "chmod",
		.enter = sys_chmod,
	},
	{
		.name = "fchmodat",
		.enter = sys_fchmodat,
	},

	{
		.name = "chown",
		.enter = sys_chown,
	},
	{
		.name = "chown32",
		.enter = sys_chown,
	},
	{
		.name = "lchown",
		.enter = sys_lchown,
	},
	{
		.name = "lchown32",
		.enter = sys_lchown,
	},
	{
		.name = "fchownat",
		.enter = sys_fchownat,
	},

	{
		.name = "mkdir",
		.enter = sys_mkdir,
	},
	{
		.name = "mkdirat",
		.enter = sys_mkdirat,
	},

	{
		.name = "mknod",
		.enter = sys_mknod,
	},
	{
		.name = "mknodat",
		.enter = sys_mknodat,
	},

	{
		.name = "rmdir",
		.enter = sys_rmdir,
	},

	{
		.name = "truncate",
		.enter = sys_truncate,
	},
	{
		.name = "truncate64",
		.enter = sys_truncate,
	},

	{
		.name = "utime",
		.enter = sys_utime,
	},
	{
		.name = "utimes",
		.enter = sys_utimes,
	},
	{
		.name = "utimensat",
		.enter = sys_utimensat,
	},
	{
		.name = "futimesat",
		.enter = sys_futimesat,
	},

	{
		.name = "unlink",
		.enter = sys_unlink,
	},
	{
		.name = "unlinkat",
		.enter = sys_unlinkat,
	},

	{
		.name = "link",
		.enter = sys_link,
	},
	{
		.name = "linkat",
		.enter = sys_linkat,
	},

	{
		.name = "rename",
		.enter = sys_rename,
	},
	{
		.name = "renameat",
		.enter = sys_renameat,
	},

	{
		.name = "symlink",
		.enter = sys_symlink,
	},
	{
		.name = "symlinkat",
		.enter = sys_symlinkat,
	},

	{
		.name = "execve",
		.enter = sys_execve,
	},

	{
		.name = "socketcall",
		.enter = sys_socketcall,
		.exit = sysx_socketcall,
	},
	{
		.name = "bind",
		.enter = sys_bind,
		.exit = sysx_bind,
	},
	{
		.name = "connect",
		.enter = sys_connect,
	},
	{
		.name = "sendto",
		.enter = sys_sendto,
	},
	{
		.name = "getsockname",
		.enter = sys_getsockname,
		.exit = sysx_getsockname,
	},

	{
		.name = "setxattr",
		.enter = sys_setxattr,
	},
	{
		.name = "lsetxattr",
		.enter = sys_lsetxattr,
	},
	{
		.name = "removexattr",
		.enter = sys_removexattr,
	},
	{
		.name = "lremovexattr",
		.enter = sys_lremovexattr,
	},

	{
		.name = "mount",
		.enter = sys_mount,
	},
	{
		.name = "umount",
		.enter = sys_umount,
	},
	{
		.name = "umount2",
		.enter = sys_umount2,
	},
};

size_t syscall_entries_max(void)
{
	return ELEMENTSOF(syscall_entries);
}

void sysinit(void)
{
	for (unsigned i = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].name) {
			systable_add(syscall_entries[i].name,
				     syscall_entries[i].enter,
				     syscall_entries[i].exit);
		} else {
			for (int abi = 0; abi < PINK_ABIS_SUPPORTED; abi++)
				systable_add_full(syscall_entries[i].no,
						  abi, NULL,
						  syscall_entries[i].enter,
						  syscall_entries[i].exit);
		}
	}
}

#ifdef WANT_SECCOMP
static size_t make_seccomp_filter(int abi, uint32_t **syscalls)
{
	unsigned i, j;
	long sysno;
	uint32_t *list;

	list = xmalloc(sizeof(uint32_t) * ELEMENTSOF(syscall_entries));
	for (i = 0, j = 0; i < ELEMENTSOF(syscall_entries); i++) {
		if (syscall_entries[i].name)
			sysno = pink_syscall_lookup(syscall_entries[i].name,
						    abi);
		else
			sysno = syscall_entries[i].no;
		if (sysno != -1)
			list[j++] = (uint32_t)sysno;
	}

	*syscalls = list;
	return j;
}

int sysinit_seccomp(void)
{
	int r, count;
	uint32_t *syscalls;

#if defined(__i386__)
	count = make_seccomp_filter(PINK_ABI_I386, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_I386, syscalls, count);

	free(syscalls);
#elif defined(__x86_64__)
	count = make_seccomp_filter(PINK_ABI_X86_64, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_X86_64, syscalls, count);
	free(syscalls);
	if (r < 0)
		return r;

	count = make_seccomp_filter(PINK_ABI_I386, &syscalls);
	r = seccomp_apply(AUDIT_ARCH_I386, syscalls, count);
	free(syscalls);
#else
#error "Platform does not support seccomp filter yet"
#endif

	return r;
}
#else
int sysinit_seccomp(void)
{
	return 0;
}
#endif

int sysenter(syd_proc_t *current)
{
	int r;
	long sysnum;
	const sysentry_t *entry;

	if ((r = syd_read_syscall(current, &sysnum)) < 0)
		return r;

	entry = systable_lookup(sysnum, GET_ABI(current));
	if (entry) {
		current->sysnum = sysnum;
		current->sysname = entry->name;
		log_syscall("entering system call");
		if (entry->enter)
			return entry->enter(current);
	} else {
		log_sys_all("entering system call %ld", sysnum);
	}

	return 0;
}

int sysexit(syd_proc_t *current)
{
	int r;
	const sysentry_t *entry;

	if (sysdeny(current)) {
		r = restore(current);
		goto out;
	}

	entry = systable_lookup(current->sysnum, GET_ABI(current));
	r = (entry && entry->exit) ? entry->exit(current) : 0;
out:
	clear_proc(current);
	return r;
}
