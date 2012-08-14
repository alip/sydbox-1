/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon privoxy which is:
 *   Copyright (c) 2001-2010 the Privoxy team. http://www.privoxy.org/
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "log.h"
#include "util.h"

/* fatal can't be turned off! */
#define LOG_LEVEL_MINIMUM	LOG_LEVEL_FATAL

/* where to log (default: stderr) */
static int logfd = -1;
static int logcfd = STDERR_FILENO;

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

PINK_GCC_ATTR((format (printf, 4, 0)))
static void log_me(int fd, int level, const char *func, const char *fmt, va_list ap)
{
	int tty;
	const char *p, *s, *l;

	tty = isatty(fd);

	switch (level) {
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

	dprintf(fd, "%s", p);
	if (prefix)
		dprintf(fd, "%s@%lu: ", prefix, time(NULL));
	if (func)
		dprintf(fd, "%s: ", func);
	vdprintf(fd, fmt, ap);
	dprintf(fd, "%s%s", s, suffix ? suffix : "");
}

int log_init(const char *filename)
{
	if (logfd > 0 && logfd != STDERR_FILENO)
		close_nointr(logfd);

	if (filename) {
		logfd = open(filename, O_WRONLY|O_APPEND|O_CREAT);
		if (logfd < 0)
			return -errno;
	} else {
		logfd = -1;
	}

	log_debug_level(debug);
	log_debug_console_level(cdebug);

	return 0;
}

void log_close(void)
{
	if (logfd > 0)
		close_nointr(logfd);
	logfd = -1;
}

void log_console_fd(int fd)
{
	logcfd = fd;
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

void log_msg_va(unsigned level, const char *fmt, va_list ap)
{
	if (logfd > 0 && (level & debug))
		log_me(logfd, level, NULL, fmt, ap);
	if (logcfd > 0 && (level & cdebug))
		log_me(logcfd, level, NULL, fmt, ap);
}

void log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}

void log_msg_va_f(unsigned level, const char *func, const char *fmt, va_list ap)
{
	if (logfd > 0 && (level & debug))
		log_me(logfd, level, func, fmt, ap);
	if (logcfd > 0 && (level & cdebug))
		log_me(logcfd, level, func, fmt, ap);
}

void log_msg_f(unsigned level, const char *func, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va_f(level, func, fmt, ap);
	va_end(ap);
}
