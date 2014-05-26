/*
 * sydbox/log.h
 *
 * Simple debug logging for sydbox.
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Ali Polatel <alip@exherbo.org>
 * Based in part upon privoxy which is:
 *   Copyright (c) 2001-2010 the Privoxy team. http://www.privoxy.org/
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef LOG_H
#define LOG_H 1

#include <stdarg.h>
#include "pink.h"

/* ANSI colour codes */
#define ANSI_NORMAL		"[00;00m"
#define ANSI_MAGENTA		"[00;35m"
#define ANSI_DARK_MAGENTA	"[01;35m"
#define ANSI_GREEN		"[00;32m"
#define ANSI_YELLOW		"[00;33m"
#define ANSI_CYAN		"[00;36m"

#define LOG_DEFAULT_PREFIX PACKAGE
#define LOG_DEFAULT_SUFFIX "\n"

/* Log levels */
#define LOG_LEVEL_WARNING	0x0001 /* warnings */
#define LOG_LEVEL_ACCESS_V	0x0002 /* access violations */
#define LOG_LEVEL_INFO		0x0004 /* messages about program workflow */
#define LOG_LEVEL_ACCESS	0x0008 /* denied/granted access */
#define LOG_LEVEL_MAGIC		0x0010 /* magic commands */
#define LOG_LEVEL_CHECK		0x0020 /* path/socket-address lookups */
#define LOG_LEVEL_MATCH		0x0040 /* pattern, socket-address matching */
#define LOG_LEVEL_TRACE		0x0080 /* trace calls */
#define LOG_LEVEL_SYSCALL	0x0100 /* intercepted system calls */
#define LOG_LEVEL_SYS_ALL	0x0800 /* all system calls */

/* Log levels below are always on: */
#define LOG_LEVEL_ASSERT	0x0200
#define LOG_LEVEL_FATAL		0x0400

int log_init(const char *filename);
void log_close(void);

void log_abort_func(void (*func)(int));
int log_console_fd(int fd);
bool log_has_level(int level);
void log_debug_level(int debug_level);
void log_debug_console_level(int debug_level);
void log_prefix(const char *p);
void log_suffix(const char *s);
void log_context(void *current);

void log_msg_va(unsigned level, const char *fmt, va_list ap)
	PINK_GCC_ATTR((format (printf, 2, 0)));
void log_msg(unsigned level, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 2, 3)));
void log_msg_errno(unsigned level, int err_no, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 3, 4)));

void die(const char *fmt, ...)
	PINK_GCC_ATTR((noreturn, format (printf, 1, 2)));
void die_errno(const char *fmt, ...)
	PINK_GCC_ATTR((noreturn, format (printf, 1, 2)));

void assert_(const char *expr, const char *func, const char *file, size_t line)
	PINK_GCC_ATTR((noreturn));
void assert_not_reached_(const char *func, const char *file, size_t line)
	PINK_GCC_ATTR((noreturn));

#define assert_not_reached() assert_not_reached_(__func__, __FILE__, __LINE__)
/* Override assert() from assert.h */
#undef assert
#ifdef NDEBUG
#define assert(expr) do {} while (0)
#else
#define assert(expr) \
	do { \
		if (!(expr)) \
			assert_(#expr, __func__, __FILE__, __LINE__); \
	} \
	while (0)
#endif

/* Short hand notations */
#define log_fatal(...)		log_msg(LOG_LEVEL_FATAL, __VA_ARGS__)
#define log_warning(...)	log_msg(LOG_LEVEL_WARNING, __VA_ARGS__)
#define log_access_v(...)	log_msg(LOG_LEVEL_ACCESS_V, __VA_ARGS__)
#define log_info(...)		log_msg(LOG_LEVEL_INFO, __VA_ARGS__)
#define err_fatal(e,...)	log_msg_errno(LOG_LEVEL_FATAL, (e), __VA_ARGS__)
#define err_warning(e,...)	log_msg_errno(LOG_LEVEL_WARNING, (e), __VA_ARGS__)

#endif
