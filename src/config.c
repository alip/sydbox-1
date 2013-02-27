/*
 * sydbox/config.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "file.h"
#include "macro.h"
#include "log.h"

void config_init(void)
{
	assert(sydbox);

	memset(&sydbox->config, 0, sizeof(config_t));
	sydbox->config.magic_core_allow = true;

	/* set sane defaults for configuration */
	sydbox->config.follow_fork = true;
	sydbox->config.exit_wait_all = true;
	sydbox->config.trace_interrupt = TRACE_INTR_WHILE_WAIT;
	sydbox->config.use_seccomp = false;
	sydbox->config.use_seize = false;
	sydbox->config.whitelist_per_process_directories = true;
	sydbox->config.whitelist_successful_bind = true;
	sydbox->config.whitelist_unsupported_socket_families = true;
	sydbox->config.abort_decision = ABORT_CONTALL;
	sydbox->config.panic_decision = PANIC_KILL;
	sydbox->config.panic_exit_code = -1;
	sydbox->config.violation_decision = VIOLATION_DENY;
	sydbox->config.violation_exit_code = -1;
	sydbox->config.child.magic_lock = LOCK_UNSET;
}

void config_done(void)
{
	if (sydbox->config.log_file) {
		free(sydbox->config.log_file);
		sydbox->config.log_file = NULL;
	}
	sydbox->config.magic_core_allow = true;
}

void config_parse_file(const char *filename)
{
	int r;
	char line[LINE_MAX];
	size_t line_count;
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp)
		die_errno("fopen(`%s')", filename);

	line_count = 0;
	while (fgets(line, LINE_MAX, fp)) {
		line_count++;
		if (line[0] == '#' || empty_line(line))
			continue;
		truncate_nl(line);
		r = magic_cast_string(NULL, line, 0);
		if (MAGIC_ERROR(r))
			die("invalid magic in file `%s' on line %zu: %s",
			    filename, line_count, magic_strerror(r));
	}

	fclose(fp);
	sydbox->config.magic_core_allow = true;
}

void config_parse_spec(const char *pathspec)
{
	size_t len;
	char *filename;

	if (pathspec[0] == SYDBOX_PROFILE_CHAR) {
		pathspec++;
		len = sizeof(DATADIR) + sizeof(PACKAGE) + strlen(pathspec) + 1;
		filename = xcalloc(len, sizeof(char));

		strcpy(filename, DATADIR "/" PACKAGE "/");
		strcat(filename, pathspec);

		config_parse_file(filename);
		free(filename);
	} else {
		config_parse_file(pathspec);
	}
}
