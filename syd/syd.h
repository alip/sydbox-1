/*
 * syd.h -- Syd's utility library
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#ifndef LIBSYD_SYD_H
#define LIBSYD_SYD_H 1

#include <sys/types.h>
#include <time.h>

size_t syd_strlcat(char *dst, const char *src, size_t siz);
size_t syd_strlcpy(char *dst, const char *src, size_t siz);

int syd_proc_open(pid_t pid);
int syd_proc_comm(int pfd, char *dst, size_t siz);
int syd_proc_cmdline(int pfd, char *dst, size_t siz);
int syd_proc_fd(pid_t pid, int fd, char **dst);

typedef void (*syd_time_prof_func_t) (void);
struct timespec syd_time_diff(const struct timespec *t1, const struct timespec *t2);

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__((sentinel))
#endif
void syd_time_prof(unsigned loop, ...);

#if !defined(SPARSE) &&\
	defined(__GNUC__) && __GNUC__ >= 4 && \
	defined(__GNUC_MINOR__) && __GNUC_MINOR__ > 5
#define assert_unreachable	__builtin_unreachable()
#else
#include <assert.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#define assert_unreachable	assert(0);
#endif

#endif
