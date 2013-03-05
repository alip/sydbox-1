/*
 * sydbox/proc.h
 *
 * /proc related utilities
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef PROC_H
#define PROC_H 1

#include <sys/types.h>

struct proc_statinfo {
	int pid;
	char comm[32];
	char state;
	int ppid;
	int pgrp;
	int session;
	int tty_nr;
	int tpgid;
	long nice;
	long num_threads;
};

int proc_cwd(pid_t pid, char **buf);
int proc_fd(pid_t pid, int dfd, char **buf);
int proc_cmdline(pid_t pid, size_t max_length, char **buf);
int proc_comm(pid_t pid, char **name);
int proc_environ(pid_t pid, char ***envp);
int proc_stat(pid_t pid, struct proc_statinfo *info);
int proc_parent(pid_t pid, pid_t *ppid); /* $ppid is tgid or ppid */

#endif /* !PROC_H */
