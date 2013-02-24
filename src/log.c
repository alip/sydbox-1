/*
 * sydbox/log.c
 *
 * Simple debug logging
 *
 * Copyright 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon privoxy which is:
 *   Copyright (c) 2001-2010 the Privoxy team. http://www.privoxy.org/
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "sydbox.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "log.h"
#include "util.h"

/* fatal can't be turned off! */
#define LOG_LEVEL_MINIMUM	(LOG_LEVEL_ASSERT|LOG_LEVEL_FATAL)

/* where to log (default: stderr) */
static FILE *logfp;
static FILE *logcfp;

/* logging detail level. */
static int debug = (LOG_LEVEL_FATAL
		    | LOG_LEVEL_WARNING
		    | LOG_LEVEL_ACCESS_V
		    | LOG_LEVEL_INFO);
static int cdebug = (LOG_LEVEL_FATAL
		     | LOG_LEVEL_WARNING
		     | LOG_LEVEL_ACCESS_V);

static const char *prefix = LOG_DEFAULT_PREFIX;
static const char *suffix = LOG_DEFAULT_SUFFIX;

static const syd_proc_t *current_proc;

/* abort function. */
static void (*abort_func)(int sig);

PINK_GCC_ATTR((format (printf, 3, 0)))
static void log_me(FILE *fp, unsigned level, const char *fmt, va_list ap)
{
	int fd, tty;
	const char *p, *s;

	if (!fp)
		return;
	fd = fileno(fp);
	if (fd < 0)
		return;
	tty = isatty(fd);

	switch (level) {
	case LOG_LEVEL_ASSERT:
	case LOG_LEVEL_FATAL:
		p = tty ? ANSI_DARK_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case LOG_LEVEL_WARNING:
	case LOG_LEVEL_ACCESS_V:
		p = tty ? ANSI_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case LOG_LEVEL_INFO:
		p = tty ? ANSI_YELLOW : "";
		s = tty ? ANSI_NORMAL : "";
	default:
		p = s = "";
		break;
	}

	fprintf(fp, "%s", p);
	if (prefix) {
		fprintf(fp, "%s@%lu:", prefix, time(NULL));
		if (current_proc) {
			fprintf(fp, " %s[%u.%d:%u]",
				current_proc->comm ? current_proc->comm
						   : sydbox->program_invocation_name,
				GET_PID(current_proc),
				GET_ABI(current_proc),
				current_proc->tgid == -1 ? 0
							 : current_proc->tgid);
			if (current_proc->sysnum != 0) {
				fprintf(fp, " sys:%ld|%s|",
					current_proc->sysnum,
					current_proc->sysname ? current_proc->sysname : "?");
			}
		}
		fputc(' ', fp);
	}
	vfprintf(fp, fmt, ap);
	fprintf(fp, "%s%s", s, suffix ? suffix : "");

	fflush(fp);
}

int log_init(const char *filename)
{
	if (logfp && logfp != stderr)
		fclose(logfp);

	if (!logcfp)
		logcfp = stderr;

	if (filename) {
		logfp = fopen(filename, "a");
		if (!logfp)
			return -errno;
		setbuf(logfp, NULL);
	} else {
		logfp = NULL;
	}

	log_debug_level(debug);
	log_debug_console_level(cdebug);

	return 0;
}

void log_close(void)
{
	if (logfp)
		fclose(logfp);
	logfp = NULL;
}

void log_abort_func(void (*func)(int))
{
	abort_func = func;
}

int log_console_fd(int fd)
{
	if (logcfp != stderr)
		fclose(logcfp);

	logcfp = fdopen(fd, "a");
	if (!logcfp)
		return -errno;

	return 0;
}

bool log_has_level(int level)
{
	if (debug & level)
		return true;
	if (logcfp && cdebug & level)
		return true;
	return false;
}

void log_debug_level(int debug_level)
{
	debug = debug_level | LOG_LEVEL_MINIMUM;
}

void log_debug_console_level(int debug_level)
{
	cdebug = debug_level | LOG_LEVEL_MINIMUM;
}

void log_prefix(const char *p)
{
	prefix = p;
}

void log_suffix(const char *s)
{
	suffix = s;
}

void log_context(void *current)
{
	current_proc = current;
}

void log_msg_va(unsigned level, const char *fmt, va_list ap)
{
	va_list aq;

	if (logcfp && (level & cdebug)) {
		va_copy(aq, ap);
		log_me(logcfp, level, fmt, aq);
		va_end(aq);
	}
	if (logfp && (level & debug)) {
		va_copy(aq, ap);
		log_me(logfp, level, fmt, aq);
		va_end(aq);
	}
}

void log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}

void log_msg_errno(unsigned level, int err_no, const char *fmt, ...)
{
	va_list ap;

	log_suffix(NULL);
	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);

	log_prefix(NULL);
	log_suffix(LOG_DEFAULT_SUFFIX);
	log_msg(level, " (errno:%d|%s| %s)", err_no, pink_name_errno(err_no, 0),
		strerror(errno));
	log_prefix(LOG_DEFAULT_PREFIX);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(LOG_LEVEL_FATAL, fmt, ap);
	va_end(ap);

	if (abort_func)
		abort_func(SIGTERM);
	exit(1);
}

void die_errno(const char *fmt, ...)
{
	va_list ap;

	log_suffix(NULL);
	va_start(ap, fmt);
	log_msg_va(LOG_LEVEL_FATAL, fmt, ap);
	va_end(ap);

	log_prefix(NULL);
	log_suffix(LOG_DEFAULT_SUFFIX);
	log_msg(LOG_LEVEL_FATAL, " (errno:%d|%s| %s)", errno,
		pink_name_errno(errno, 0), strerror(errno));
	log_prefix(LOG_DEFAULT_PREFIX);

	if (abort_func)
		abort_func(SIGTERM);
	exit(1);
}

void assert_(const char *expr, const char *func,
		 const char *file, size_t line)
{
	log_msg(LOG_LEVEL_ASSERT,
		"Assertion '%s' failed at %s:%zu, function %s()",
		expr, file, line, func);

	if (abort_func)
		abort_func(SIGTERM);
	abort();
}

void assert_not_reached_(const char *func, const char *file, size_t line)
{
	log_msg(LOG_LEVEL_ASSERT,
		"Code must not be reached at %s:%zu, function %s()",
		file, line, func);

	if (abort_func)
		abort_func(SIGTERM);
	abort();
}
