/*
 * libsyd/proc.c
 *
 * /proc utilities
 *
 * Copyright (c) 2014, 2015, 2016 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#include "syd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef O_PATH /* hello glibc, I hate you. */
#define O_PATH 010000000
#endif

/*
 * 16 is sufficient since the largest number we will ever convert
 * will be 2^32-1, which is 10 digits.
 */
#define SYD_INT_MAX 16
#define SYD_PID_MAX SYD_INT_MAX
#define SYD_PROC_MAX (sizeof("/proc/%u") + SYD_PID_MAX)
#define SYD_PROC_FD_MAX (SYD_PROC_MAX + sizeof("/fd") + SYD_PID_MAX)
#define SYD_PROC_TASK_MAX (SYD_PROC_MAX + sizeof("/task") + SYD_PID_MAX)
#define SYD_PROC_STATUS_LINE_MAX sizeof("Tgid:") + SYD_INT_MAX + 16 /* padding */

static void chomp(char *str)
{
	char *c;

	for (c = str; *c != '\0'; c++) {
		if (*c == '\n') {
			*c = '\0';
			break;
		}
	}
}

static void convert_zeroes(char *str, char *end)
{
	char *c;
	size_t i;

	for(i = 0, c = str; c != end; i++, c++) {
		if (*c == '\0')
			*c = ' ';
	}
}

int syd_proc_open(pid_t pid)
{
	int r, fd;
	char p[SYD_PROC_MAX];

	if (pid <= 0)
		return -EINVAL;

	r = snprintf(p, sizeof(p), "/proc/%u", pid);
	if (r < 0 || (size_t)r >= sizeof(p))
		return -EINVAL;

	fd = open(p, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	return (fd < 0) ? -errno : fd;
}

int syd_proc_fd_open(pid_t pid)
{
	int r, fd;
	char p[SYD_PROC_FD_MAX];

	if (pid <= 0)
		return -EINVAL;

	r = snprintf(p, sizeof(p), "/proc/%u/fd", pid);
	if (r < 0 || (size_t)r >= sizeof(p))
		return -EINVAL;

	fd = open(p, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	return (fd < 0) ? -errno : fd;
}

int syd_proc_ppid(pid_t pid, pid_t *ppid)
{
	int pfd, fd, save_errno;
	pid_t ppid_r;
	FILE *f;

	if (pid <= 0 || ppid == NULL)
		return -EINVAL;

	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "stat", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;
	f = fdopen(fd, "r");
	if (!f) {
		save_errno = errno;
		close(fd);
		return -save_errno;
	}

	/* L_MAX is:
	 * 2 * SYD_PID_MAX: Process PID + Process Parent PID
	 * 16: `comm' maximum length (defined as char comm[17] in kernel
	 *           task_struct
	 * 6: The rest: PID + ' (' + comm + ') ' + state[1] + ' ' + PID
	 * 1: '\0'
	 */
#	define L_MAX ((2*SYD_PID_MAX) + 16 + 6 + 1)
	/* Careful here: `comm' may have spaces or numbers ( or '()' ?) in it!
	 * e.g: perl-5.10.2 test-suite t/op/magic.t -> "Good Morning"
	 */
	int i;
	char *c, l[L_MAX];

	if (fgets(l, L_MAX - 2, f) == NULL) {
		fclose(f);
		return -EINVAL;
	}
	l[L_MAX - 1] = '\0';

	/* Search for ')' from the end. */
	for (i = L_MAX - 2; i > 0 && l[i] != ')'; i--);

	if (i <= 0 || (i + 4 >= L_MAX)) {
		fclose(f);
		return -EINVAL;
	}

	c = l + (i + 4); /* Skip ' T ' -> space + state + space */
	if (sscanf(c, "%d", &ppid_r) != 1) {
		fclose(f);
		return -EINVAL;
	}

	fclose(f);
	*ppid = ppid_r;

	return 0;
}

int syd_proc_parents(pid_t pid, pid_t *ppid, pid_t *tgid)
{
	int pfd, fd, save_errno;
	pid_t ppid_r, tgid_r;
	FILE *f;

	if (pid <= 0)
		return -EINVAL;
	if (!ppid && !tgid)
		return -EINVAL;

	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "status", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;
	f = fdopen(fd, "r");
	if (!f) {
		save_errno = errno;
		close(fd);
		return -save_errno;
	}

	bool seen_ppid, seen_tgid;
	char *c, l[SYD_PROC_STATUS_LINE_MAX];

	ppid_r = 0, tgid_r = 0;
	seen_ppid = false, seen_tgid = false;
	while (fgets(l, SYD_PROC_STATUS_LINE_MAX - 1, f) != NULL) {
		if (!seen_tgid && !strncmp(l, "Tgid:", sizeof("Tgid:") - 1)) {
			seen_tgid = true;
			if (tgid) {
				for (c = l + sizeof("Tgid:") - 1;
				     *c == ' ' || *c == '\t'; c++); /* skip space */
				if (sscanf(c, "%d", &tgid_r) != 1) {
					fclose(f);
					return -EINVAL;
				}
			}
			if (!ppid)
				break;
		} else if (!seen_ppid && !strncmp(l, "PPid:", sizeof("PPid:") - 1)) {
			seen_ppid = true;
			if (ppid) {
				for (c = l + sizeof("PPid:") - 1;
				     *c == ' ' || *c == '\t'; c++); /* skip space */
				if (sscanf(c, "%d", &ppid_r) != 1) {
					fclose(f);
					return -EINVAL;
				}
			}
			break;
		}
	}

	fclose(f);

	if (tgid) {
		if (seen_tgid)
			*tgid = tgid_r;
		else
			return -EINVAL;
	}
	if (ppid) {
		if (seen_ppid)
			*ppid = ppid_r;
		else
			return -EINVAL;
	}

	return 0;
}

int syd_proc_comm(pid_t pid, char *dst, size_t siz)
{
	int pfd, fd, save_errno;

	if (pid <= 0)
		return -EINVAL;

	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "comm", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;

	char *s = dst;
	size_t nleft = siz - 1;
	while (nleft > 0) {
		ssize_t n;

		n = read(fd, s, nleft);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -errno;
		}

		if (n == 0)
			break;

		s += n;
		nleft -= n;
	}

	close(fd);
	*s = '\0';
	chomp(dst);

	return 0;
}

int syd_proc_cmdline(pid_t pid, char *dst, size_t siz)
{
	int pfd, fd, save_errno;

	if (pid <= 0)
		return -EINVAL;

	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "cmdline", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;

	char *s = dst;
	size_t nleft = siz - 1;
	ssize_t n;
	while (nleft > 0) {
		n = read(fd, s, nleft);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -errno;
		}

		if (n == 0)
			break;

		s += n;
		nleft -= n;
	}

	close(fd);
	*s = '\0';
	convert_zeroes(dst, s);
	return 0;
}

int syd_proc_state(pid_t pid, char *state)
{
	int pfd, fd, save_errno;
	char state_r;
	FILE *f;

	if (pid <= 0)
		return -EINVAL;
	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "stat", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;
	f = fdopen(fd, "r");
	if (!f) {
		save_errno = errno;
		close(fd);
		return -save_errno;
	}

	if (fscanf(f, "%*d %*s %c", &state_r) != 1) {
		fclose(f);
		return -EINVAL;
	}

	fclose(f);
	*state = state_r;

	return 0;
}

int syd_proc_fd_path(pid_t pid, int fd, char **dst)
{
	int pfd, r;
	char sfd[SYD_INT_MAX];

	if (pid <= 0 || fd < 0)
		return -EINVAL;

	pfd = syd_proc_fd_open(pid);
	if (pfd < 0)
		return -errno;
	r = snprintf(sfd, sizeof(sfd), "%u", fd);
	if (r < 0 || (size_t)r >= sizeof(sfd)) {
		close(pfd);
		return -EINVAL;
	}

	char *path = NULL;
	size_t len = 128; /* most paths are short */

	for (;;) {
		char *p;
		ssize_t s, n;

		p = realloc(path, len * sizeof(char));
		if (!p) {
			if (path)
				free(path);
			close(pfd);
			return -errno;
		}
		path = p;

		/* Careful here, readlinkat(2) does not append '\0' */
		s = (len - 1) * sizeof(char);
		n = readlinkat(pfd, sfd, path, s);
		if (n < s) {
			path[n] = '\0';
			*dst = path;
			close(pfd);
			return n;
		}

		/* Truncated, try again with a larger buffer */
		if (len > (SIZE_MAX - len)) {
			/* There is a limit for everything */
			free(p);
			close(pfd);
			return -ENAMETOOLONG;
		}
		len *= 2;
	}
	/* never reached */
}

int syd_proc_environ(pid_t pid)
{
	int c, pfd, fd, save_errno;
	FILE *f;
	/* <linux/binfmts.h> states ARG_MAX_STRLEN is essentially random and
	 * here (x86_64) defines it as (PAGE_SIZE * 32), I am more modest. */
	char s[1024];

	if (pid <= 0)
		return -EINVAL;

	pfd = syd_proc_open(pid);
	if (pfd < 0)
		return -errno;
	fd = openat(pfd, "environ", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	save_errno = errno;
	close(pfd);
	if (fd < 0)
		return -save_errno;
	f = fdopen(fd, "r");
	if (!f) {
		save_errno = errno;
		close(fd);
		return -save_errno;
	}

	int i = 0, r = 0;
	while ((c = fgetc(f)) != EOF) {
		s[i] = c;

		if (c == '\0') { /* end of unit */
			if (putenv(s) != 0) {
				r = -ENOMEM;
				break;
			} else {
				i = 0;
				s[0] = '\0';
				continue;
			}
		}

		if (++i >= 1024) {
			r = -E2BIG;
			break;
		}
	}

	fclose(f);
	return r;
}

int syd_proc_task_find(pid_t pid, pid_t pid_task)
{
	int r;
	char p[SYD_PROC_TASK_MAX + 1 /* '/' */ + SYD_PID_MAX];

	if (pid <= 0 || pid_task <= 0)
		return -EINVAL;

	r = snprintf(p, sizeof(p), "/proc/%u/task/%u", pid, pid_task);
	if (r < 0 || (size_t)r >= sizeof(p))
		return -EINVAL;

	errno = 0;
	access(p, F_OK);
	return -errno;
}

int syd_proc_task_open(pid_t pid, DIR **task_dir)
{
	int r, fd;
	char p[SYD_PROC_TASK_MAX];
	DIR *d;

	if (pid <= 0 || !task_dir)
		return -EINVAL;

	r = snprintf(p, sizeof(p), "/proc/%u/task", pid);
	if (r < 0 || (size_t)r >= sizeof(p))
		return -EINVAL;

	fd = open(p, O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	if (fd < 0)
		return -errno;

	d = fdopendir(fd);
	if (!d)
		return -errno;

	*task_dir = d;
	return 0;
}

int syd_proc_task_next(DIR *task_dir, pid_t *task_pid)
{
	pid_t p;
	struct dirent *dent;

	if (!task_dir || !task_pid)
		return -EINVAL;

retry:
	errno = 0;
	dent = readdir(task_dir);
	if (!dent) {
		if (!errno)
			p = 0;
		else
			return -errno;
	} else if (dent->d_name[0] == '.') {
		goto retry;
	} else {
		p = atol(dent->d_name);
	}

	*task_pid = p;
	return 0;
}
