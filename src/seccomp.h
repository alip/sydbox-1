/*
 * sydbox/seccomp.h
 *
 * seccomp support
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2012 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef SECCOMP_H
#define SECCOMP_H 1

#include <stdint.h>
#include <linux/audit.h>

int seccomp_init(void);
int seccomp_apply(int arch, uint32_t *syscalls, int count);

#endif
