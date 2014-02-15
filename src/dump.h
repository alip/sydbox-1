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

#define DUMPF_PROCFS	0x00000100 /* read /proc/$pid/stat */
#define DUMPF_SYSARGV	0x00000200 /* decode system call arguments */
#define DUMPF_SANDBOX	0x00000400 /* dump process sandbox */

enum dump {
	DUMP_INIT,
	DUMP_CLOSE,
	DUMP_FLUSH,
	DUMP_STATE_CHANGE, /* waitpid(2) */
	DUMP_PTRACE_EXECVE, /* PTRACE_EVENT_EXEC */
	DUMP_PTRACE_CLONE, /* PTRACE_EVENT_{FORK,VORK,CLONE} */
	DUMP_PTRACE_STEP, /* PTRACE_SYSCALL or PTRACE_RESUME */
	DUMP_THREAD_NEW, /* new_thread() */
	DUMP_THREAD_FREE, /* free_process() */
	DUMP_PTRACE_REGSET, /* TODO */
};

void dump(enum dump what, ...);

#endif
