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

#ifndef HAVE_CONFIG_H
# include "config.h"
#endif

#if SYDBOX_DUMP

#include <errno.h>

# define DUMP_FMT  1
# define DUMP_ENV  "SHOEBOX"    /* read pathname from environment variable */
# define DUMP_NAME "./sydcore"  /* Default dump name */

# define DUMPF_PROCFS	0x00000100 /* read /proc/$pid/stat */
# define DUMPF_SYSARGV	0x00000200 /* decode system call arguments */
# define DUMPF_SANDBOX	0x00000400 /* dump process sandbox */

enum dump {
	DUMP_INIT,
	DUMP_CLOSE,
	DUMP_FLUSH,
	DUMP_INTERRUPT, /* interrupted */
	DUMP_WAIT, /* waitpid(2) */
	DUMP_PINK, /* calls to pinktrace */
	DUMP_THREAD_NEW, /* new_thread() */
	DUMP_THREAD_FREE, /* free_process() */
};

void dump(enum dump what, ...);

#else
# define dump(...) /* empty */
#endif /* SYDBOX_DUMP */

#endif
