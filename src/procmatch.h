/*
 * sydbox/procmatch.h
 *
 * match proc/ whitelists efficiently
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#ifndef PROCMATCH_H
#define PROCMATCH_H 1

#include "sydhash.h"

typedef struct {
	pid_t pid;
	char path[sizeof("/proc/%u/***") + sizeof(int)*3 + /*paranoia:*/16];
	UT_hash_handle hh;
} proc_pid_t;

int procadd(proc_pid_t **pp, pid_t pid);
int procdrop(proc_pid_t **pp, pid_t pid);
int procmatch(proc_pid_t **pp, const char *path);

#endif
