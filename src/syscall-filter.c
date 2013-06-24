/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <errno.h>
#include <stdint.h>

#if SYDBOX_HAVE_SECCOMP
# include "seccomp.h"
# include <sys/mman.h>
#endif

int filter_mmap(int arch, uint32_t sysnum)
{
#if SYDBOX_HAVE_SECCOMP
	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	struct sock_filter mmap_filter[] = {
		/* check for arch & syscall_nr */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
		/* check for PROT_WRITE & MAP_SHARED */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysnum, 0, 5),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(2)), /* prot */
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~PROT_WRITE, 3, 0),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_arg(3)), /* flags */
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, ~MAP_SHARED, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(EINVAL & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};
	struct sock_fprog prog;

	memset(&prog, 0, sizeof(prog));
	prog.filter = mmap_filter;
	prog.len = ELEMENTSOF(mmap_filter);

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -errno;
#endif
	return 0;
}

int sys_fallback_mmap(syd_proc_t *current)
{
	int r;
	int prot, flags;

	if (!sydbox->config.restrict_shared_memory_writable)
		return 0;

	if ((r = syd_read_argument_int(current, 2, &prot)) < 0)
		return r;
	if ((r = syd_read_argument_int(current, 3, &flags)) < 0)
		return r;

	r = 0;
	if (prot & PROT_WRITE && flags & MAP_SHARED)
		r = deny(current, EINVAL);
	return r;
}
