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

#ifndef LOG_H
#define LOG_H 1

#include <stdarg.h>
#include <pinktrace/compiler.h>

#define LOG_DEFAULT_PREFIX PACKAGE
#define LOG_DEFAULT_SUFFIX "\n"

/* Log levels */
#define LOG_LEVEL_ACCESS_V	0x0001 /* log access violations */
#define LOG_LEVEL_INFO		0x0002 /* log messages about program workflow */
#define LOG_LEVEL_ACCESS	0x0004 /* log denied/granted access */
#define LOG_LEVEL_MAGIC		0x0008 /* log magic commands */
#define LOG_LEVEL_CHECK		0x0010 /* log path/socket-address lookups and checks */
#define LOG_LEVEL_MATCH		0x0020 /* log pattern matching, socket-address matching */
#define LOG_LEVEL_TRACE		0x0040 /* log trace calls */
#define LOG_LEVEL_SYSCALL	0x0080 /* log intercepted system calls */
#define LOG_LEVEL_SYS_ALL	0x0400 /* log all system calls */

/* Log levels below are always on: */
#define LOG_LEVEL_WARNING	0x0100
#define LOG_LEVEL_FATAL		0x0200

int log_init(const char *filename);
void log_close(void);
void log_console_fd(int fd);
void log_debug_level(int debug_level);
void log_debug_console_level(int debug_level);
void log_prefix(const char *p);
void log_suffix(const char *s);
void log_msg_va(unsigned level, const char *fmt, va_list ap) PINK_GCC_ATTR((format (printf, 2, 0)));
void log_msg_va_f(unsigned level, const char *func, const char *fmt, va_list ap) PINK_GCC_ATTR((format (printf, 2, 0)));
void log_msg(unsigned level, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));
void log_msg_f(unsigned level, const char *func, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 3, 4)));

/* Shorthand notations */
#define log_fatal(...)		log_msg_f(LOG_LEVEL_FATAL, __func__, __VA_ARGS__)
#define log_warning(...)	log_msg_f(LOG_LEVEL_WARNING, __func__, __VA_ARGS__)
#define log_access_v(...)	log_msg(LOG_LEVEL_ACCESS_V, __VA_ARGS__) /* treat specially */
#define log_info(...)		log_msg_f(LOG_LEVEL_INFO, __func__, __VA_ARGS__)
#define log_access(...)		log_msg_f(LOG_LEVEL_ACCESS, __func__, __VA_ARGS__)
#define log_magic(...)		log_msg_f(LOG_LEVEL_MAGIC, __func__, __VA_ARGS__)
#define log_match(...)		log_msg_f(LOG_LEVEL_MATCH, __func__, __VA_ARGS__)
#define log_check(...)		log_msg_f(LOG_LEVEL_CHECK, __func__, __VA_ARGS__)
#define log_trace(...)		log_msg_f(LOG_LEVEL_TRACE, __func__, __VA_ARGS__)
#define log_syscall(...)	log_msg_f(LOG_LEVEL_SYSCALL, __func__, __VA_ARGS__)
#define log_sys_all(...)	log_msg_f(LOG_LEVEL_SYS_ALL, __func__, __VA_ARGS__)

#endif
