/*
 * sydbox/sydbox-syscall.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox-defs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

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

int sysenter(struct pink_easy_process *current)
{
	int r;
	long no;
	const char *name;
	pid_t tid;
	enum pink_abi abi;
	proc_data_t *data;
	const sysentry_t *entry;

	tid = pink_easy_process_get_tid(current);
	abi = pink_easy_process_get_abi(current);
	data = pink_easy_process_get_userdata(current);

	if ((r = pink_read_syscall(tid, abi, &data->regs, &no)) < 0) {
		if (r != -ESRCH) {
			log_warning("read_syscall(%lu, %d) failed"
				    " (errno:%d %s)",
				    (unsigned long)tid, abi,
				    -errno, strerror(-errno));
			return panic(current);
		}
		log_trace("read_syscall(%lu, %d) failed (errno:%d %s)",
			  (unsigned long)tid, abi,
			  -errno, strerror(-errno));

		return PINK_EASY_CFLAG_DROP;
	}

	data->sno = no;
	entry = systable_lookup(no, abi);
	if (entry) {
		log_syscall("process %s[%lu:%u] entered syscall=`%s'(%ld)",
			    data->comm, (unsigned long)tid, abi,
			    entry->name, no);
		if (entry->enter)
			return entry->enter(current, entry->name);
	} else {
		log_sys_all("process %s[%lu:%u] entered syscall=%ld",
			    data->comm, (unsigned long)tid, abi, no);
	}

	return 0;
}

int sysexit(struct pink_easy_process *current)
{
	int r;
	const sysentry_t *entry;
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->deny) {
		r = restore(current);
		goto end;
	}

	entry = systable_lookup(data->sno, abi);
	r = (entry && entry->exit) ? entry->exit(current, entry->name) : 0;
end:
	clear_proc(data);
	return r;
}
