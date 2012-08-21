/*
 * sydbox/log.h
 *
 * Simple debug logging for sydbox.
 *
 * Copyright 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon privoxy which is:
 *   Copyright (c) 2001-2010 the Privoxy team. http://www.privoxy.org/
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef LOG_H
#define LOG_H 1

#include <stdarg.h>
#include <pinktrace/compiler.h>

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

extern int log_init(const char *filename);
extern void log_close(void);

extern int log_console_fd(int fd);
extern void log_debug_level(int debug_level);
extern void log_debug_console_level(int debug_level);
extern void log_prefix(const char *p);
extern void log_suffix(const char *s);

extern void log_msg_va(unsigned level, const char *fmt, va_list ap)
	PINK_GCC_ATTR((format (printf, 2, 0)));
extern void log_msg_va_f(unsigned level, const char *func,
			 const char *fmt, va_list ap)
	PINK_GCC_ATTR((format (printf, 2, 0)));

extern void log_msg(unsigned level, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 2, 3)));
extern void log_msg_f(unsigned level, const char *func, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 3, 4)));

extern void die(const char *fmt, ...)
	PINK_GCC_ATTR((noreturn, format (printf, 1, 2)));
extern void die_errno(const char *fmt, ...)
	PINK_GCC_ATTR((noreturn, format (printf, 1, 2)));

extern void assert_(const char *expr, const char *func,
		    const char *file, size_t line)
	PINK_GCC_ATTR((noreturn));
extern void assert_not_reached_(const char *func, const char *file,
				size_t line)
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
#define log_fatal(...)		log_msg_f(LOG_LEVEL_FATAL, \
				  __func__, __VA_ARGS__)
#define log_warning(...)	log_msg_f(LOG_LEVEL_WARNING, \
					  __func__, __VA_ARGS__)
#define log_access_v(...)	log_msg(LOG_LEVEL_ACCESS_V, \
					__VA_ARGS__) /* treat specially */
#define log_info(...)		log_msg_f(LOG_LEVEL_INFO, \
					  __func__, __VA_ARGS__)
#define log_access(...)		log_msg_f(LOG_LEVEL_ACCESS, \
					  __func__, __VA_ARGS__)
#define log_magic(...)		log_msg_f(LOG_LEVEL_MAGIC, \
					  __func__, __VA_ARGS__)
#define log_match(...)		log_msg_f(LOG_LEVEL_MATCH, \
					  __func__, __VA_ARGS__)
#define log_check(...)		log_msg_f(LOG_LEVEL_CHECK, \
					  __func__, __VA_ARGS__)
#define log_trace(...)		log_msg_f(LOG_LEVEL_TRACE, \
					  __func__, __VA_ARGS__)
#define log_syscall(...)	log_msg_f(LOG_LEVEL_SYSCALL, \
					  __func__, __VA_ARGS__)
#define log_sys_all(...)	log_msg_f(LOG_LEVEL_SYS_ALL, \
					  __func__, __VA_ARGS__)

#endif
