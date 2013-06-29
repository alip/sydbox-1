/*
 * sydbox/seccomp.h
 *
 * seccomp support
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2012 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef SECCOMP_H
#define SECCOMP_H 1

#include "sydconf.h"

#if SYDBOX_HAVE_SECCOMP
# include <sys/prctl.h>
# include <linux/types.h>
# include <linux/unistd.h>
# include <linux/audit.h>
# include <linux/filter.h>
# include <linux/seccomp.h>

# define syscall_nr (offsetof(struct seccomp_data, nr))
# define arch_nr (offsetof(struct seccomp_data, arch))
# define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#endif

#include <stdint.h>
#include <linux/audit.h>

int seccomp_init(void);
int seccomp_apply(int arch, uint32_t *syscalls, int count);

#endif
