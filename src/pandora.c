/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Pandora's Box. pandora is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pandora is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "pandora-defs.h"

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

pandora_t *pandora = NULL;

static void
about(void)
{
	printf(PACKAGE"-"VERSION GITHEAD"\n");
}

PINK_NORETURN
static void
usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITHEAD" -- Pandora's Box\n\
usage: "PACKAGE" [-hVv] [-c pathspec] ... [-m magic] ... [-p pid] ... \n\
   or: "PACKAGE" [-hVv] [-c pathspec] ... [-m magic] ... [-E var=val] ... [command [arg ...]]\n\
-h          -- Show usage and exit\n\
-V          -- Show version and exit\n\
-v          -- Be verbose, may be repeated\n\
-c pathspec -- path spec to the configuration file\n\
-m magic    -- run a magic command during init, may be repeated\n\
-p pid      -- trace processes with process id, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n");
	exit(code);
}

static void
pandora_init(const char *progname)
{
	assert(!pandora);

	pandora = xcalloc(1, sizeof(pandora_t));
	pandora->progname = progname ? progname : PACKAGE;
	pandora->tbl = NULL;
	pandora->ctx = NULL;
	config_init();
}

static void
pandora_destroy(void)
{
	assert(pandora);
	assert(pandora->config);

	if (pandora->tbl)
		free(pandora->tbl);
	if (pandora->ctx)
		pink_easy_context_destroy(pandora->ctx);

	config_destroy();

	slist_free(pandora->config->trace.kill_if_match, free);
	slist_free(pandora->config->trace.resume_if_match, free);

	slist_free(pandora->config->filter.exec, free);
	slist_free(pandora->config->filter.path, free);
	slist_free(pandora->config->filter.sock, free);

	free(pandora->config);
	free(pandora);
	pandora = NULL;

	log_close();
}

int
main(int argc, char **argv)
{
	int core, opt, ptrace_options, ret;
	unsigned pid_count;
	pid_t pid;
	pid_t *pid_list;
	const char *env;

	/* Initialize Pandora */
	pandora_init(argv[0]);

	/* Allocate pids array */
	pid_count = 0;
	pid_list = xmalloc(argc * sizeof(pid_t));

	core = 1;
	while ((opt = getopt(argc, argv, "hVvc:m:p:E:")) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
		case 'V':
			about();
			return 0;
		case 'v':
			++pandora->config->core.log.level;
			break;
		case 'c':
			config_reset();
			config_parse_file(optarg, core > 0);
			--core;
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

	if ((env = getenv(PANDORA_CONFIG_ENV))) {
		config_reset();
		config_parse_file(env, core > 0);
	}

	/* Initialize logging */
	log_init();

	/* Configuration is done */
	config_destroy();

	/* Initialize callbacks */
	callback_init();
	sysinit();

	ptrace_options = TRACE_OPTIONS;
	if (pandora->config->core.trace.followfork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK | PINK_TRACE_OPTION_VFORK | PINK_TRACE_OPTION_CLONE);

	if (!(pandora->ctx = pink_easy_context_new(ptrace_options, pandora->tbl, NULL, NULL)))
		die_errno(-1, "pink_easy_context_new");

	if (!pid_count) {
		free(pid_list);

		if ((ret = pink_easy_execvp(pandora->ctx, argv[optind], &argv[optind])))
			die_errno(1, "pink_easy_execvp");

		ret = pink_easy_loop(pandora->ctx);
		pandora_destroy();
		return ret;
	}

	for (unsigned i = 0; i < pid_count; i++) {
		if ((ret = pink_easy_attach(pandora->ctx, pid_list[i])))
			die_errno(1, "pink_easy_attach(%d)", pid_list[i]);
	}
	free(pid_list);

	ret = pink_easy_loop(pandora->ctx);
	pandora_destroy();
	return ret;
}
