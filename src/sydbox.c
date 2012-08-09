/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
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

/*
 * The function sydbox_attach_all() is based in part upon strace which is:
 *
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
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

#include <assert.h>
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
#include <getopt.h>

#include "macro.h"
#include "util.h"

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
usage: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] {-p pid...}\n\
   or: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-V          -- Show version and exit\n\
-v          -- Be verbose, may be repeated\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-p pid      -- trace processes with process id, may be repeated\n\
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
	sydbox->wait_execve = 0;
	sydbox->violation = false;
	sydbox->ctx = NULL;
	config_init();
}

static void sydbox_destroy(void)
{
	struct snode *node;

	assert(sydbox);

	/* Free the global configuration */
	free_sandbox(&sydbox->config.child);

	SLIST_FLUSH(node, &sydbox->config.exec_kill_if_match, up, free);
	SLIST_FLUSH(node, &sydbox->config.exec_resume_if_match, up, free);

	SLIST_FLUSH(node, &sydbox->config.filter_exec, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_read, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_write, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_network, up, free_sock_match);

	pink_easy_context_destroy(sydbox->ctx);

	free(sydbox->program_invocation_name);
	free(sydbox);
	sydbox = NULL;

	systable_free();
	log_close();
}

static void sig_cleanup(int signo)
{
	struct sigaction sa;

	fprintf(stderr, "\ncaught signal %d exiting\n", signo);

	abort_all();

	sigaction(signo, NULL, &sa);
	sa.sa_handler = SIG_DFL;
	sigaction(signo, &sa, NULL);
	raise(signo);
}

static bool dump_one_process(struct pink_easy_process *current, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(current);
	pid_t tgid = pink_easy_process_get_tgid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	struct snode *node;

	fprintf(stderr, "-- Thread ID: %lu\n", (unsigned long)tid);
	if (pink_easy_process_is_suspended(current)) {
		fprintf(stderr, "   Thread is suspended at startup!\n");
		return true;
	}
	fprintf(stderr, "   Thread Group ID: %lu\n", tgid > 0 ? (unsigned long)tgid : 0UL);
	fprintf(stderr, "   Attach: %s\n", pink_easy_process_is_attached(current) ? "true" : "false");
	fprintf(stderr, "   Clone: %s\n", pink_easy_process_is_clone(current) ? "true" : "false");
	fprintf(stderr, "   Comm: %s\n", data->comm);
	fprintf(stderr, "   Cwd: %s\n", data->cwd);
	fprintf(stderr, "   Syscall: {no:%lu abi:%d name:%s}\n", data->sno, abi, pink_syscall_name(data->sno, abi));

	if (!PTR_TO_UINT(userdata))
		return true;

	fprintf(stderr, "--> Sandbox: {exec:%s read:%s write:%s sock:%s}\n",
			sandbox_mode_to_string(data->config.sandbox_exec),
			sandbox_mode_to_string(data->config.sandbox_read),
			sandbox_mode_to_string(data->config.sandbox_write),
			sandbox_mode_to_string(data->config.sandbox_network));
	fprintf(stderr, "    Magic Lock: %s\n", lock_state_to_string(data->config.magic_lock));
	fprintf(stderr, "    Exec Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_exec, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	fprintf(stderr, "    Read Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_read, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	fprintf(stderr, "    Write Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_write, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	/* TODO:  SLIST_FOREACH(node, data->config.whitelist_sock, up) */

	return true;
}

static void sig_user(int signo)
{
	bool cmpl;
	unsigned c;
	struct pink_easy_process_list *list;

	if (!sydbox)
		return;

	cmpl = signo == SIGUSR2;
	list = pink_easy_context_get_process_list(sydbox->ctx);

	fprintf(stderr, "\nReceived SIGUSR%s, dumping %sprocess tree\n",
			cmpl ? "2" : "1",
			cmpl ? "complete " : "");
	c = pink_easy_process_list_walk(list, dump_one_process, UINT_TO_PTR(cmpl));
	fprintf(stderr, "Tracing %u process%s\n", c, c > 1 ? "es" : "");
}

static unsigned sydbox_attach_all(pid_t pid)
{
	char *ptask;
	DIR *dir;

	if (!sydbox->config.follow_fork)
		goto one;

	/* Read /proc/$pid/task and attach to all threads */
	xasprintf(&ptask, "/proc/%lu/task", (unsigned long)pid);
	dir = opendir(ptask);
	free(ptask);

	if (dir) {
		unsigned ntid = 0, nerr = 0;
		struct dirent *de;
		pid_t tid;

		while ((de = readdir(dir))) {
			if (de->d_fileno == 0)
				continue;
			if (parse_pid(de->d_name, &tid) < 0)
				continue;
			++ntid;
			if (!pink_easy_attach(sydbox->ctx, tid, tid != pid ? pid : -1)) {
				warning("failed to attach to tid:%lu (errno:%d %s)",
						(unsigned long)tid,
						errno, strerror(errno));
				++nerr;
			}

		}
		closedir(dir);
		ntid -= nerr;
		return ntid;
	}

	warning("failed to open /proc/%lu/task (errno:%d %s)",
			(unsigned long)pid,
			errno, strerror(errno));
one:
	if (!pink_easy_attach(sydbox->ctx, pid, -1)) {
		warning("failed to attach process:%lu (errno:%d %s)",
				(unsigned long)pid,
				errno, strerror(errno));
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	int opt, ptrace_options, ret;
	unsigned pid_count;
	pid_t pid;
	pid_t *pid_list;
	const char *env;
	struct sigaction sa;
	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'V'},
		{"profile",	required_argument,	NULL,	0},
		{NULL,		0,		NULL,	0},
	};

	/* Initialize Sydbox */
	sydbox_init();

	/* Allocate pids array */
	pid_count = 0;
	pid_list = xmalloc(argc * sizeof(pid_t));

	while ((opt = getopt_long(argc, argv, "hVvc:m:p:E:", long_options, &options_index)) != EOF) {
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
		case 'V':
			about();
			return 0;
		case 'v':
			sydbox->config.log_level++;
			break;
		case 'c':
			config_reset();
			config_parse_spec(optarg);
			break;
		case 'm':
			ret = magic_cast_string(NULL, optarg, 0);
			if (ret < 0)
				die(1, "invalid magic: `%s': %s", optarg, magic_strerror(ret));
			break;
		case 'p':
			if ((ret = parse_pid(optarg, &pid)) < 0) {
				errno = -ret;
				die_errno(1, "invalid process id `%s'", optarg);
			}
			if (pid == getpid())
				die(1, "tracing self is not possible");

			pid_list[pid_count++] = pid;
			break;
		case 'E':
			if (putenv(optarg))
				die_errno(1, "putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if ((optind == argc) && !pid_count)
		usage(stderr, 1);

	if ((env = getenv(SYDBOX_CONFIG_ENV))) {
		config_reset();
		config_parse_spec(env);
	}

	pink_easy_init();
	log_init();
	config_done();
	callback_init();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK | PINK_TRACE_OPTION_VFORK | PINK_TRACE_OPTION_CLONE);

	if (!(sydbox->ctx = pink_easy_context_new(ptrace_options, &sydbox->callback_table, NULL, NULL)))
		die_errno(-1, "pink_easy_context_new");

	if (pid_count == 0) {
		/* Ignore two execve(2) related events
		 * 1. PTRACE_EVENT_EXEC
		 * 2. SIGTRAP | 0x80 (stop after execve system call)
		 */
		sydbox->wait_execve = 2;
		sydbox->program_invocation_name = xstrdup(argv[optind]);

		/* Set useful environment variables for children */
		setenv("SYDBOX_ACTIVE", "1", 1);
		setenv("SYDBOX_VERSION", VERSION, 1);

		/* Poison! */
		if (streq(argv[optind], "/bin/sh"))
			fprintf(stderr, "[01;35m" PINK_FLOYD "[00;00m");

		if (!pink_easy_execvp(sydbox->ctx, argv[optind], &argv[optind]))
			die(1, "failed to execute child process");
	}
	else {
		unsigned npid = 0;
		for (unsigned i = 0; i < pid_count; i++)
			npid += sydbox_attach_all(pid_list[i]);
		if (!npid)
			die(1, "failed to attach to any process");
	}
	free(pid_list);

	/* Handle signals */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = SIG_IGN;
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);

	sa.sa_handler = sig_cleanup;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = sig_user;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

	ret = pink_easy_loop(sydbox->ctx, PINK_EASY_STEP_SYSCALL);
	sydbox_destroy();
	return ret;
}
