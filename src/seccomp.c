/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * The function seccomp_apply() is based in part upon systemd which is:
 *   Copyright 2012 Lennart Poettering
 *   Distributed under the terms of the GNU Lesser General Public License v2.1 or later
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "seccomp.h"
#include <errno.h>

#ifdef WANT_SECCOMP
#include "macro.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

int seccomp_init(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -errno;
	return 0;
}

int seccomp_apply(int arch, uint32_t *syscalls, int count)
{
	const struct sock_filter header[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
	};
	const struct sock_filter footer[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};

	int i;
	unsigned n = count;
	struct sock_filter *f;
	struct sock_fprog prog;

	if (!syscalls)
		return -EINVAL;

	/* Build the filter program from a header, the syscall matches
	 * and the footer */
	f = alloca(sizeof(struct sock_filter) * (ELEMENTSOF(header) + 2*n + ELEMENTSOF(footer)));
	memcpy(f, header, sizeof(header));

	for (i = 0, n = 0; i < count; i++) {
		struct sock_filter item[] = {
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscalls[i], 0, 1),
			BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE|(syscalls[i] & SECCOMP_RET_DATA))
		};

		f[ELEMENTSOF(header) + 2*n] = item[0];
		f[ELEMENTSOF(header) + 2*n+1] = item[1];

		n++;
	}

	memcpy(f + ELEMENTSOF(header) + 2*n, footer, sizeof(footer));

	/* Install the filter */
	memset(&prog, 0, sizeof(prog));
	prog.len = ELEMENTSOF(header) + ELEMENTSOF(footer) + 2*n;
	prog.filter = f;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -errno;

	return 0;
}
#else
int seccomp_init(void)
{
	return -ENOTSUP;
}

int seccomp_apply(uint32_t *syscall_filter)
{
	return -ENOTSUP;
}
#endif
