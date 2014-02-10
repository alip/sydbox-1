/*
 * sydbox/dump.h
 *
 * Event dumper using JSON lines
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#ifndef DUMP_H
#define DUMP_H

#define DUMP_ENV "SHOEBOX"
#define DUMP_FMT 1
#define DUMP_PROCFS 0x00000100
#define DUMP_SANDBOX 0x00000200

enum dump {
	DUMP_INIT,
	DUMP_CLOSE,
	DUMP_FLUSH,
	DUMP_STATE_CHANGE, /* waitpid(2) */
	DUMP_PTRACE_EXECVE, /* PTRACE_EVENT_EXEC */
	DUMP_PTRACE_STEP, /* PTRACE_SYSCALL or PTRACE_RESUME */
};

void dump(enum dump what, ...);

#endif
