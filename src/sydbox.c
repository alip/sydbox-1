/*
 * sydbox/sydbox.c
 *
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
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sydbox-defs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <getopt.h>

#include "macro.h"
#include "pathlookup.h"
#include "proc.h"
#include "log.h"
#include "util.h"
#ifdef WANT_SECCOMP
#include "seccomp.h"
#endif

/* pink floyd */
#define PINK_FLOYD	"       ..uu.                               \n" \
			"       ?$\"\"`?i           z'              \n" \
			"       `M  .@\"          x\"               \n" \
			"       'Z :#\"  .   .    f 8M              \n" \
			"       '&H?`  :$f U8   <  MP   x#'         \n" \
			"       d#`    XM  $5.  $  M' xM\"          \n" \
			"     .!\">     @  'f`$L:M  R.@!`           \n" \
			"    +`  >     R  X  \"NXF  R\"*L           \n" \
			"        k    'f  M   \"$$ :E  5.           \n" \
			"        %%    `~  \"    `  'K  'M          \n" \
			"            .uH          'E   `h           \n" \
			"         .x*`             X     `          \n" \
			"      .uf`                *                \n" \
			"    .@8     .                              \n" \
			"   'E9F  uf\"          ,     ,             \n" \
			"     9h+\"   $M    eH. 8b. .8    .....     \n" \
			"    .8`     $'   M 'E  `R;'   d?\"\"\"`\"# \n" \
			"   ` E      @    b  d   9R    ?*     @     \n" \
			"     >      K.zM `%%M'   9'    Xf   .f     \n" \
			"    ;       R'          9     M  .=`       \n" \
			"    t                   M     Mx~          \n" \
			"    @                  lR    z\"           \n" \
			"    @                  `   ;\"             \n" \
			"                          `                \n"

sydbox_t *sydbox = NULL;

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION"\n");
}

PINK_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- ptrace based sandbox\n\
usage: "PACKAGE" [-hv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n\
\n\
Hey you, out there beyond the wall,\n\
Breaking bottles in the hall,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

static void sydbox_init(void)
{
	assert(!sydbox);

	sydbox = xmalloc(sizeof(sydbox_t));
	sydbox->eldest = -1;
	sydbox->exit_code = 0;
	sydbox->execve_status = WAIT_EXECVE;
	sydbox->violation = false;
	sydbox->ctx = NULL;
	config_init();
	log_init(NULL);
}

static void sydbox_destroy(void)
{
	struct snode *node;

	assert(sydbox);

	/* Free the global configuration */
	free_sandbox(&sydbox->config.child);

	SLIST_FREE_ALL(node, &sydbox->config.exec_kill_if_match, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.exec_resume_if_match, up, free);

	SLIST_FREE_ALL(node, &sydbox->config.filter_exec, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_read, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_write, up, free);
	SLIST_FREE_ALL(node, &sydbox->config.filter_network, up,
		       free_sockmatch);

	pink_easy_context_destroy(sydbox->ctx);

	free(sydbox->program_invocation_name);
	free(sydbox);
	sydbox = NULL;

	systable_free();
	log_close();
}

static bool dump_one_process(struct pink_easy_process *current, void *userdata)
{
	int r;
	const char *CG, *CB, *CN, *CI, *CE; /* good, bad, important, normal end */
	bool verbose = !!PTR_TO_UINT(userdata);
	struct proc_statinfo info;

	pid_t tid = pink_easy_process_get_tid(current);
	pid_t tgid = pink_easy_process_get_tgid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	short flags = pink_easy_process_get_flags(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	struct snode *node;
	struct sockmatch *match;

	if (isatty(STDERR_FILENO)) {
		CG = ANSI_GREEN;
		CB = ANSI_DARK_MAGENTA;
		CI = ANSI_CYAN;
		CN = ANSI_YELLOW;
		CE = ANSI_NORMAL;
	} else {
		CG = CB = CI = CN = CE = "";
	}

	fprintf(stderr, "%s-- Information on Thread ID: %lu%s\n", CG, (unsigned long)tid, CE);
	if ((r = proc_stat(tid, &info)) < 0) {
		fprintf(stderr, "%sproc_stat failed (errno:%d %s)%s\n", CB, errno, strerror(errno), CE);
	} else {
		fprintf(stderr, "\t%sproc: pid=%d ppid=%d pgrp=%d%s\n",
				CI,
				info.pid, info.ppid, info.pgrp,
				CE);
		fprintf(stderr, "\t%sproc: comm=`%s' state=`%c'%s\n",
				CI,
				info.comm, info.state,
				CE);
		fprintf(stderr, "\t%sproc: session=%d tty_nr=%d tpgid=%d%s\n",
				CI,
				info.session, info.tty_nr, info.tpgid,
				CE);
		fprintf(stderr, "\t%sproc: nice=%ld num_threads=%ld%s\n",
				CI,
				info.nice, info.num_threads,
				CE);
	}

	if (flags & PINK_EASY_PROCESS_SUSPENDED) {
		fprintf(stderr, "\t%sThread is suspended at startup!%s\n", CB, CE);
		return true;
	}
	fprintf(stderr, "\t%sThread Group ID: %lu%s\n", CN, tgid > 0 ? (unsigned long)tgid : 0UL, CE);
	fprintf(stderr, "\t%sComm: `%s'%s\n", CN, data->comm, CE);
	fprintf(stderr, "\t%sCwd: `%s'%s\n", CN, data->cwd, CE);
	fprintf(stderr, "\t%sSyscall: {no:%lu abi:%d name:%s}%s\n", CN,
			data->sno, abi, pink_syscall_name(data->sno, abi),
			CE);

	if (!verbose)
		return true;

	fprintf(stderr, "\t%sSandbox: {exec:%s read:%s write:%s sock:%s}%s\n",
			CN,
			sandbox_mode_to_string(data->config.sandbox_exec),
			sandbox_mode_to_string(data->config.sandbox_read),
			sandbox_mode_to_string(data->config.sandbox_write),
			sandbox_mode_to_string(data->config.sandbox_network),
			CE);
	fprintf(stderr, "\t%sMagic Lock: %s%s\n", CN, lock_state_to_string(data->config.magic_lock), CE);
	fprintf(stderr, "\t%sExec Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &data->config.whitelist_exec, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sRead Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &data->config.whitelist_read, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sWrite Whitelist:%s\n", CI, CE);
	SLIST_FOREACH(node, &data->config.whitelist_write, up)
		fprintf(stderr, "\t\t%s`%s'%s\n", CN, (char *)node->data, CE);
	fprintf(stderr, "\t%sNetwork Whitelist bind():%s\n", CI, CE);
	SLIST_FOREACH(node, &data->config.whitelist_network_bind, up) {
		match = node->data;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, match, CE);
		}
	}
	fprintf(stderr, "\t%sNetwork Whitelist connect():%s\n", CI, CE);
	SLIST_FOREACH(node, &data->config.whitelist_network_connect, up) {
		match = node->data;
		if (match->str) {
			fprintf(stderr, "\t\t%s`%s'%s\n", CN, match->str, CE);
		} else {
			fprintf(stderr, "\t\t%s((%p))%s\n", CN, match, CE);
		}
	}

	return true;
}

static void sig_user(int signo)
{
	bool complete_dump;
	unsigned all;
	struct pink_easy_process_list *list;

	if (!sydbox)
		return;

	complete_dump= !!(signo == SIGUSR2);
	list = pink_easy_context_get_process_list(sydbox->ctx);

	fprintf(stderr, "\nReceived SIGUSR%s, dumping %sprocess tree\n",
			complete_dump ? "2" : "1",
			complete_dump ? "complete " : "");
	all = pink_easy_process_list_walk(list, dump_one_process, BOOL_TO_PTR(complete_dump));
	fprintf(stderr, "Tracing %u process%s\n", all, all > 1 ? "es" : "");
}

static void sydbox_startup_child(char **argv)
{
	int r;
	struct stat statbuf;
	const char *filename;
	char *pathname;
	pid_t pid = 0;
	struct pink_easy_process *current;

	r = path_lookup(argv[0], &pathname);
	if (r < 0) {
		errno = -r;
		die_errno("exec");
	}

	pid = fork();
	if (pid < 0)
		die_errno("Can't fork");
	else if (pid == 0) {
#ifdef WANT_SECCOMP
		int r;

		if (sydbox->config.use_seccomp) {
			if ((r = seccomp_init()) < 0) {
				fprintf(stderr,
					"seccomp_init failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}

			if ((r = sysinit_seccomp()) < 0) {
				fprintf(stderr,
					"seccomp_apply failed (errno:%d %s)\n",
					-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}
#endif
		pid = getpid();
		if (!pink_trace_me()) {
			fprintf(stderr,
				"ptrace(TRACEME) failed (errno:%d %s)\n",
				errno, strerror(errno));
			_exit(EXIT_FAILURE);
		}

		kill(pid, SIGSTOP);

		execv(pathname, argv);
		fprintf(stderr, "execv failed (errno:%d %s)\n", errno, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	free(pathname);

	current = pink_easy_process_new(sydbox->ctx, pid, -1,
					PINK_EASY_PROCESS_IGNORE_ONE_SIGSTOP);
	if (current == NULL) {
		kill(pid, SIGKILL);
		die_errno("process_new failed, killed %lu", (unsigned long)pid);
	}
}

int main(int argc, char **argv)
{
	int opt, r;
	pid_t pid;
	const char *env;
	struct sigaction sa;

	int ptrace_options;
	enum pink_easy_step ptrace_default_step;

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"profile",	required_argument,	NULL,	0},
		{NULL,		0,		NULL,	0},
	};

	/* Initialize Sydbox */
	sydbox_init();

	/* Make sure SIGCHLD has the default action so that waitpid
	   definitely works without losing track of children.  The user
	   should not have given us a bogus state to inherit, but he might
	   have.  Arguably we should detect SIG_IGN here and pass it on
	   to children, but probably noone really needs that.  */
	signal(SIGCHLD, SIG_DFL);

	while ((opt = getopt_long(argc, argv, "hvc:m:E:", long_options, &options_index)) != EOF) {
		switch (opt) {
		case 0:
			if (streq(long_options[options_index].name, "profile")) {
				profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 1));
				profile_name[0] = SYDBOX_PROFILE_CHAR;
				strcat(profile_name, optarg);
				config_reset();
				config_parse_spec(profile_name);
				free(profile_name);
				break;
			}
			usage(stderr, 1);
		case 'h':
			usage(stdout, 0);
		case 'v':
			about();
			return 0;
		case 'c':
			config_reset();
			config_parse_spec(optarg);
			break;
		case 'm':
			r = magic_cast_string(NULL, optarg, 0);
			if (MAGIC_ERROR(r))
				die("invalid magic: `%s': %s",
				    optarg, magic_strerror(r));
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (optind == argc)
		usage(stderr, 1);

	if ((env = getenv(SYDBOX_CONFIG_ENV))) {
		config_reset();
		config_parse_spec(env);
	}

	config_done();

	pink_easy_init();
	callback_init();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC;
	ptrace_default_step = PINK_EASY_STEP_SYSCALL;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK
				| PINK_TRACE_OPTION_VFORK
				| PINK_TRACE_OPTION_CLONE);
	if (sydbox->config.use_seccomp) {
#ifdef WANT_SECCOMP
		ptrace_options |= PINK_TRACE_OPTION_SECCOMP;
		ptrace_default_step = PINK_EASY_STEP_RESUME;
#else
		log_info("seccomp: not supported, disabling");
		sydbox->config.use_seccomp = false;
#endif
	}

	sydbox->ctx = pink_easy_context_new(ptrace_options, &sydbox->callback_table, NULL, NULL);
	if (sydbox->ctx == NULL)
		die_errno("context_new");

	/* Set default ptrace stepping */
	pink_easy_context_set_step(sydbox->ctx, ptrace_default_step);

	/*
	 * Initial program_invocation_name to be used for data->comm.
	 * Saves one proc_comm() call.
	 */
	sydbox->program_invocation_name = xstrdup(argv[optind]);

	/* Set useful environment variables for children */
	setenv("SYDBOX_ACTIVE", "1", 1);
	setenv("SYDBOX_VERSION", VERSION, 1);

	/* Poison! */
	if (streq(argv[optind], "/bin/sh"))
		fprintf(stderr, "[01;35m" PINK_FLOYD "[00;00m");

	/* STARTUP_CHILD must be called before the signal handlers get
	   installed below as they are inherited into the spawned process.
	   Also we do not need to be protected by them as during interruption
	   in the STARTUP_CHILD mode we kill the spawned process anyway.  */
	sydbox_startup_child(&argv[optind]);

	pink_easy_interrupt_init(sydbox->config.trace_interrupt);
	signal(SIGUSR1, sig_user);
	signal(SIGUSR2, sig_user);

	r = pink_easy_loop(sydbox->ctx);

	sydbox_destroy();

	return r;
}
