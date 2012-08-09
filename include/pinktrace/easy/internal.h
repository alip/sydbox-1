/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace which is:
 *   Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 *   Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 *   Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 *   Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LpIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PINK_EASY_INTERNAL_H
#define PINK_EASY_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <pinktrace/internal.h> /* _pink_assert_not_reached() */
#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#undef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/** We have attached to this process, but did not see it stopping yet */
#define PINK_EASY_PROCESS_STARTUP		00001
/** Next SIGSTOP is to be ignored */
#define PINK_EASY_PROCESS_IGNORE_ONE_SIGSTOP	00002
/** Process is suspended, waiting for its parent */
#define PINK_EASY_PROCESS_SUSPENDED		00004
/** A system call is in progress **/
#define PINK_EASY_PROCESS_INSYSCALL		00010
/** It is attached already **/
#define PINK_EASY_PROCESS_ATTACHED		00020
/** Process should have forks followed **/
#define PINK_EASY_PROCESS_FOLLOWFORK		00040
/** Process is a clone **/
#define PINK_EASY_PROCESS_CLONE_THREAD		00100

#ifdef __cplusplus
extern "C" {
#endif

/** Process entry **/
struct pink_easy_process {
	/** PINK_EASY_PROCESS_* flags **/
	short flags;

	/** Thread ID of this entry **/
	pid_t tid;

	/** Thread group of this entry **/
	pid_t tgid;

	/** System call ABI (e.g. 32bit, 64bit) of this process **/
	enum pink_abi abi;

	/** Per-process user data **/
	void *userdata;

	/** Destructor for user data **/
	pink_easy_free_func_t userdata_destroy;

	SLIST_ENTRY(pink_easy_process) entries;
};
SLIST_HEAD(pink_easy_process_list, pink_easy_process);

/** Tracing context **/
struct pink_easy_context {
	/** Number of processes */
	unsigned nprocs;

	/** pink_trace_setup() options **/
	int ptrace_options;

	/** Last error **/
	enum pink_easy_error error;

	/** Was the error fatal? **/
	bool fatal;

	/** Process list */
	struct pink_easy_process_list process_list;

	/** Callback table **/
	struct pink_easy_callback_table callback_table;

	/** User data **/
	void *userdata;

	/** Destructor for the user data **/
	pink_easy_free_func_t userdata_destroy;
};
#define PINK_EASY_FOREACH_PROCESS(node, ctx)	SLIST_FOREACH((node), &(ctx)->process_list, entries)
#define PINK_EASY_INSERT_PROCESS(ctx, current)							\
	do {											\
		(current) = calloc(1, sizeof(*(current)));					\
		if ((current) == NULL) {							\
			(ctx)->callback_table.error((ctx), PINK_EASY_ERROR_ALLOC, "calloc");	\
		} else {									\
			SLIST_INSERT_HEAD(&(ctx)->process_list, (current), entries);		\
			(ctx)->nprocs++;							\
		}										\
	} while (0)
#define PINK_EASY_REMOVE_PROCESS(ctx, current)							\
	do {											\
		SLIST_REMOVE(&(ctx)->process_list, (current), pink_easy_process, entries);	\
		if ((current)->userdata_destroy && (current)->userdata) {			\
			(current)->userdata_destroy((current)->userdata);			\
		}										\
		free(current);									\
		(ctx)->nprocs--;								\
	} while (0)

#ifdef __cplusplus
}
#endif
#endif
