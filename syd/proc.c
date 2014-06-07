/*
 * libsyd/proc.c
 *
 * /proc utilities
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "syd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
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

	fd = open(p, O_PATH|O_DIRECTORY|O_NOFOLLOW);
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

	fd = open(p, O_PATH|O_DIRECTORY|O_NOFOLLOW);
	return (fd < 0) ? -errno : fd;
}

int syd_proc_comm(int pfd, char *dst, size_t siz)
{
	int fd;

	if (pfd < 0)
		return -EINVAL;

	fd = openat(pfd, "comm", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	if (fd < 0)
		return -errno;

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

int syd_proc_cmdline(int pfd, char *dst, size_t siz)
{
	int fd;

	if (pfd < 0)
		return -EINVAL;

	fd = openat(pfd, "cmdline", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
	if (fd < 0)
		return -errno;

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

int syd_proc_fd_path(int pfd, int fd, char **dst)
{
	int r;
	char sfd[SYD_INT_MAX];

	if (pfd < 0 || fd < 0)
		return -EINVAL;

	r = snprintf(sfd, sizeof(sfd), "%u", fd);
	if (r < 0 || (size_t)r >= sizeof(sfd))
		return -EINVAL;

	char *path = NULL;
	size_t len = 128; /* most paths are short */

	for (;;) {
		char *p;
		ssize_t s, n;

		p = realloc(path, len * sizeof(char));
		if (!p) {
			if (path)
				free(path);
			return -errno;
		}
		path = p;

		/* Careful here, readlinkat(2) does not append '\0' */
		s = (len - 1) * sizeof(char);
		n = readlinkat(pfd, sfd, path, s);
		if (n < s) {
			path[n] = '\0';
			*dst = path;
			return n;
		}

		/* Truncated, try again with a larger buffer */
		if (len > (SIZE_MAX - len)) {
			/* There is a limit for everything */
			free(p);
			return -ENAMETOOLONG;
		}
		len *= 2;
	}
	/* never reached */
}
