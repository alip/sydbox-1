/*
 * sydbox/proc.c
 *
 * /proc related utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "proc.h"

#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
# define PAGE_SIZE sysconf(_SC_PAGESIZE)
#endif
#include <linux/binfmts.h>

#include "file.h"
#include "macro.h"
#include "log.h"
#include "util.h"

/* Useful macros */
#ifndef MAX
#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

/*
 * resolve /proc/$pid/cwd
 */
int proc_cwd(pid_t pid, char **buf)
{
	int r;
	char *cwd, *linkcwd;
	struct stat s;

	assert(pid >= 1);
	assert(buf);

	if (asprintf(&linkcwd, "/proc/%lu/cwd", (unsigned long)pid) < 0)
		return -ENOMEM;

	r = readlink_alloc(linkcwd, &cwd);
	free(linkcwd);
	if (r)
		return r;

	/* If the current working directory of a process is removed after the
	 * process started, /proc/$pid/cwd is a dangling symbolic link and
	 * points to "/path/to/current/working/directory (deleted)".
	 */
	if (stat(cwd, &s) && errno == ENOENT) {
		char *c;
		if ((c = strrchr(cwd, ' ')))
			cwd[c - cwd] = '\0';
	}

	*buf = cwd;
	return 0;
}

/*
 * resolve /proc/$pid/fd/$dirfd
 */
int proc_fd(pid_t pid, int dfd, char **buf)
{
	int r;
	char *fd, *linkdir;

	assert(pid >= 1);
	assert(dfd >= 0);
	assert(buf);

	if (asprintf(&linkdir, "/proc/%lu/fd/%d", (unsigned long)pid, dfd) < 0)
		return -ENOMEM;

	r = readlink_alloc(linkdir, &fd);
	free(linkdir);
	if (r == 0)
		*buf = fd;
	return r;
}

/*
 * read /proc/$pid/cmdline,
 * does not handle kernel threads which can't be traced anyway.
 */
int proc_cmdline(pid_t pid, size_t max_length, char **buf)
{
	char *p, *r, *k;
	int c;
	bool space = false;
	size_t left;
	FILE *f;

	assert(pid >= 1);
	assert(max_length > 0);
	assert(buf);

	if (asprintf(&p, "/proc/%lu/cmdline", (unsigned long)pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	r = malloc(max_length * sizeof(char));
	if (!r) {
		fclose(f);
		return -ENOMEM;
	}

	k = r;
	left = max_length;
	while ((c = getc(f)) != EOF) {
		if (isprint(c)) {
			if (space) {
				if (left <= 4)
					break;

				*(k++) = ' ';
				left--;
				space = false;
			}

			if (left <= 4)
				break;

			*(k++) = (char)c;
			left--;
		}
		else
			space = true;
	}

	if (left <= 4) {
		size_t n = MIN(left - 1, 3U);
		memcpy(k, "...", n);
		k[n] = 0;
	}
	else
		*k = 0;

	fclose(f);
	*buf = r;
	return 0;
}

/*
 * read /proc/$pid/comm
 */
int proc_comm(pid_t pid, char **name)
{
	int r;
	char *p;

	assert(pid >= 1);
	assert(name);

	if (asprintf(&p, "/proc/%lu/comm", (unsigned long)pid) < 0)
		return -ENOMEM;

	r = read_one_line_file(p, name);
	free(p);

	if (r < 0)
		return r;

	return 0;
}

/*
 * read /proc/$pid/environ
 */
int proc_environ(pid_t pid, char ***envp)
{
	int c, r;
	unsigned i, j;
	char *p;
	FILE *f;
	char **env = NULL;

	assert(pid >= 1);
	assert(envp);

	if (asprintf(&p, "/proc/%lu/environ", (unsigned long)pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);
	if (!f)
		return -errno;

	i = 0;
	env = malloc(sizeof(char *) * (i+2));
	if (!env)
		return -ENOMEM;
	env[i] = malloc(sizeof(char) * MAX_ARG_STRLEN);
	if (!env[i])
		return -ENOMEM;
	env[i][0] = '\0';
	env[i+1] = NULL;
	j = 0;
	while ((c = fgetc(f)) != EOF) {
		if (j >= MAX_ARG_STRLEN) {
			r = -E2BIG;
			goto err;
		}
		env[i][j] = c;
		if (c == '\0') { /* end of unit */
			i++;
			if (i+2 >= MAX_ARG_STRINGS) {
				r = -E2BIG;
				goto err;
			}
			env = realloc(env, sizeof(char *) * (i+2));
			if (!env)
				return -ENOMEM;
			env[i] = malloc(sizeof(char) * MAX_ARG_STRLEN);
			if (!env[i])
				return -ENOMEM;
			env[i][0] = '\0';
			env[i+1] = NULL;
			j = 0;
		} else {
			j++;
		}
	}

	fclose(f);

	*envp = env;
	return 0;
err:
	for (i = 0; i < ELEMENTSOF(env); i++) {
		if (env[i])
			free(env[i]);
	}
	free(env);

	return r;
}

/*
 * read /proc/$pid/stat
 */
int proc_stat(pid_t pid, struct proc_statinfo *info)
{
	char *p;
	FILE *f;

	assert(pid >= 1);
	assert(info);

	if (asprintf(&p, "/proc/%lu/stat", (unsigned long)pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	if (fscanf(f,
		"%d"	/* pid */
		" %32s"	/* comm */
		" %c"	/* state */
		" %d"	/* ppid */
		" %d"	/* pgrp */
		" %d"	/* session */
		" %d"	/* tty_nr */
		" %d"	/* tpgid */
		" %*u"	/* flags */
		" %*u %*u %*u %*u" /* minflt, cminflt, majflt, cmajflt */
		" %*u %*u %*d %*d" /* utime, stime, cutime, cstime */
		" %*d"	/* priority */
		" %ld" /* nice */
		" %ld", /* num_threads */
			&info->pid,
			info->comm,
			&info->state,
			&info->ppid,
			&info->pgrp,
			&info->session,
			&info->tty_nr,
			&info->tpgid,
			&info->nice,
			&info->num_threads) != 10) {
		fclose(f);
		return -EINVAL;
	}

	fclose(f);
	return 0;
}
