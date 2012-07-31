/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
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

#ifndef SYDBOX_GUARD_DEFS_H
#define SYDBOX_GUARD_DEFS_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE 1
#endif /* !_ATFILE_SOURCE */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/un.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "JSON_parser.h"
#include "hashtable.h"
#include "slist.h"
#include "util.h"

/* Definitions */
#ifndef SYDBOX_PATH_MAX
#if defined(PATH_MAX)
#define SYDBOX_PATH_MAX (PATH_MAX+1)
#elif defined(MAXPATHLEN)
#define SYDBOX_PATH_MAX (MAXPATHLEN+1)
#else
#define SYDBOX_PATH_MAX (256+1)
#endif
#endif

#ifndef SYDBOX_PROFILE_CHAR
#define SYDBOX_PROFILE_CHAR '@'
#endif /* !SYDBOX_PROFILE_CHAR */

#ifndef SYDBOX_CONFIG_ENV
#define SYDBOX_CONFIG_ENV "SYDBOX_CONFIG"
#endif /* !SYDBOX_CONFIG_ENV */

#ifndef SYDBOX_JSON_DEBUG_ENV
#define SYDBOX_JSON_DEBUG_ENV "SYDBOX_JSON_DEBUG"
#endif /* !SYDBOX_JSON_DEBUG_ENV */

#ifndef SYDBOX_MAGIC_PREFIX
#define SYDBOX_MAGIC_PREFIX "/dev/sydbox"
#endif /* !SYDBOX_MAGIC_PREFIX */

#ifndef SYDBOX_MAGIC_SEP_CHAR
#define SYDBOX_MAGIC_SEP_CHAR ':'
#endif /* !SYDBOX_MAGIC_SEP_CHAR */

#ifndef SYDBOX_MAGIC_QUERY_CHAR
#define SYDBOX_MAGIC_QUERY_CHAR '?'
#endif /* !SYDBOX_MAGIC_QUERY_CHAR */

#ifndef SYDBOX_MAGIC_ADD_CHAR
#define SYDBOX_MAGIC_ADD_CHAR '+'
#endif /* !SYDBOX_MAGIC_ADD_CHAR */

#ifndef SYDBOX_MAGIC_REMOVE_CHAR
#define SYDBOX_MAGIC_REMOVE_CHAR '-'
#endif /* !SYDBOX_MAGIC_REMOVE_CHAR */

/* Enumerations */
enum sandbox_mode {
	SANDBOX_OFF,
	SANDBOX_ALLOW,
	SANDBOX_DENY,
};
static const char *const sandbox_mode_table[] = {
	[SANDBOX_OFF] = "off",
	[SANDBOX_DENY] = "deny",
	[SANDBOX_ALLOW] = "allow",
};
DEFINE_STRING_TABLE_LOOKUP(sandbox_mode, int)

enum create_mode {
	NO_CREATE,
	MAY_CREATE,
	MUST_CREATE,
};

enum lock_state {
	LOCK_UNSET,
	LOCK_SET,
	LOCK_PENDING,
};
static const char *const lock_state_table[] = {
	[LOCK_UNSET] = "off",
	[LOCK_SET] = "on",
	[LOCK_PENDING] = "exec",
};
DEFINE_STRING_TABLE_LOOKUP(lock_state, int)

enum abort_decision {
	ABORT_KILLALL,
	ABORT_CONTALL,
};
static const char *const abort_decision_table[] = {
	[ABORT_KILLALL] = "killall",
	[ABORT_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(abort_decision, int)

enum panic_decision {
	PANIC_KILL,
	PANIC_CONT,
	PANIC_CONTALL,
	PANIC_KILLALL,
};
static const char *const panic_decision_table[] = {
	[PANIC_KILL] = "kill",
	[PANIC_CONT] = "cont",
	[PANIC_CONTALL] = "contall",
	[PANIC_KILLALL] = "killall",
};
DEFINE_STRING_TABLE_LOOKUP(panic_decision, int)

enum violation_decision {
	VIOLATION_DENY,
	VIOLATION_KILL,
	VIOLATION_KILLALL,
	VIOLATION_CONT,
	VIOLATION_CONTALL,
};
static const char *const violation_decision_table[] = {
	[VIOLATION_DENY] = "deny",
	[VIOLATION_KILL] = "kill",
	[VIOLATION_KILLALL] = "killall",
	[VIOLATION_CONT] = "cont",
	[VIOLATION_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(violation_decision, int)

enum log_level {
	LOG_LEVEL_FATAL,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_INFO,
	LOG_LEVEL_MESSAGE,
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_TRACE,
};
static const char *const log_level_table[] = {
	[LOG_LEVEL_FATAL] = "fatal",
	[LOG_LEVEL_WARNING] = "warning",
	[LOG_LEVEL_INFO] = "info",
	[LOG_LEVEL_MESSAGE] = "message",
	[LOG_LEVEL_DEBUG] = "debug",
	[LOG_LEVEL_TRACE] = "trace",
};
DEFINE_STRING_TABLE_LOOKUP(log_level, int)

#define MAGIC_QUERY_TRUE	1
#define MAGIC_QUERY_FALSE	2

enum magic_type {
	MAGIC_TYPE_NONE,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_INTEGER,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,

	MAGIC_TYPE_INVALID,
};

enum magic_key {
	MAGIC_KEY_NONE,

	MAGIC_KEY_VERSION,

	MAGIC_KEY_CORE,

	MAGIC_KEY_CORE_SANDBOX,
	MAGIC_KEY_CORE_SANDBOX_EXEC,
	MAGIC_KEY_CORE_SANDBOX_READ,
	MAGIC_KEY_CORE_SANDBOX_WRITE,
	MAGIC_KEY_CORE_SANDBOX_NETWORK,

	MAGIC_KEY_CORE_WHITELIST,
	MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES,
	MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND,
	MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES,

	MAGIC_KEY_CORE_ABORT,
	MAGIC_KEY_CORE_ABORT_DECISION,

	MAGIC_KEY_CORE_PANIC,
	MAGIC_KEY_CORE_PANIC_DECISION,
	MAGIC_KEY_CORE_PANIC_EXIT_CODE,

	MAGIC_KEY_CORE_VIOLATION,
	MAGIC_KEY_CORE_VIOLATION_DECISION,
	MAGIC_KEY_CORE_VIOLATION_EXIT_CODE,
	MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL,
	MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE,

	MAGIC_KEY_CORE_TRACE,
	MAGIC_KEY_CORE_TRACE_FOLLOW_FORK,
	MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL,
	MAGIC_KEY_CORE_TRACE_MAGIC_LOCK,

	MAGIC_KEY_LOG,
	MAGIC_KEY_LOG_CONSOLE_FD,
	MAGIC_KEY_LOG_FILE,
	MAGIC_KEY_LOG_LEVEL,
	MAGIC_KEY_LOG_TIMESTAMP,

	MAGIC_KEY_EXEC,
	MAGIC_KEY_EXEC_KILL_IF_MATCH,
	MAGIC_KEY_EXEC_RESUME_IF_MATCH,

	MAGIC_KEY_WHITELIST,
	MAGIC_KEY_WHITELIST_EXEC,
	MAGIC_KEY_WHITELIST_READ,
	MAGIC_KEY_WHITELIST_WRITE,
	MAGIC_KEY_WHITELIST_NETWORK,
	MAGIC_KEY_WHITELIST_NETWORK_BIND,
	MAGIC_KEY_WHITELIST_NETWORK_CONNECT,

	MAGIC_KEY_BLACKLIST,
	MAGIC_KEY_BLACKLIST_EXEC,
	MAGIC_KEY_BLACKLIST_READ,
	MAGIC_KEY_BLACKLIST_WRITE,
	MAGIC_KEY_BLACKLIST_NETWORK,
	MAGIC_KEY_BLACKLIST_NETWORK_BIND,
	MAGIC_KEY_BLACKLIST_NETWORK_CONNECT,

	MAGIC_KEY_FILTER,
	MAGIC_KEY_FILTER_EXEC,
	MAGIC_KEY_FILTER_READ,
	MAGIC_KEY_FILTER_WRITE,
	MAGIC_KEY_FILTER_NETWORK,

	MAGIC_KEY_INVALID,
};

enum magic_error {
	MAGIC_ERROR_SUCCESS = 0,
	MAGIC_ERROR_INVALID_KEY = -1,
	MAGIC_ERROR_INVALID_TYPE = -2,
	MAGIC_ERROR_INVALID_VALUE = -3,
	MAGIC_ERROR_INVALID_QUERY = -4,
	MAGIC_ERROR_INVALID_OPERATION = -5,
	MAGIC_ERROR_NOPERM = -6,
	MAGIC_ERROR_OOM = -7,
};

/* Type declarations */
typedef struct {
	char *path;
	struct pink_sockaddr *addr;
} sock_info_t;

typedef struct {
	/* The actual pattern, useful for disallowing */
	char *str;

	int family;

	union {
		struct {
			bool abstract;
			char *path;
		} sa_un;

		struct {
			unsigned netmask;
			unsigned port[2];
			struct in_addr addr;
		} sa_in;

#if SYDBOX_HAVE_IPV6
		struct {
			unsigned netmask;
			unsigned port[2];
			struct in6_addr addr;
		} sa6;
#endif
	} match;
} sock_match_t;

typedef struct {
	enum sandbox_mode sandbox_exec;
	enum sandbox_mode sandbox_read;
	enum sandbox_mode sandbox_write;
	enum sandbox_mode sandbox_network;

	enum lock_state magic_lock;

	slist_t whitelist_exec;
	slist_t whitelist_read;
	slist_t whitelist_write;
	slist_t whitelist_network_bind;
	slist_t whitelist_network_connect;

	slist_t blacklist_exec;
	slist_t blacklist_read;
	slist_t blacklist_write;
	slist_t blacklist_network_bind;
	slist_t blacklist_network_connect;
} sandbox_t;

typedef struct {
	/* Last system call */
	unsigned long sno;

	/* Process registers */
	const pink_regs_t *regs;

	/* Arguments of last system call */
	long args[PINK_MAX_ARGS];

	/* Last (socket) subcall */
	long subcall;

	/* Is the last system call denied? */
	bool deny;

	/* Denied system call will return this value */
	long retval;

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;

	/* Current working directory, read from /proc/$pid/cwd */
	char *cwd;

	/* Process name, read from /proc/$pid/comm for initial process and
	 * updated after successful execve() */
	char *comm;

	/* Information about the last bind address with port zero */
	sock_info_t *savebind;

	/* fd -> sock_info_t mappings  */
	hashtable_t *sockmap;

	/* Per-process configuration */
	sandbox_t config;
} proc_data_t;

typedef struct config_state config_state_t;

typedef struct {
	/* Config parser & state */
	bool core_disallow;
	JSON_parser parser;
	config_state_t *state;

	/* Per-process sandboxing data */
	sandbox_t child;

	/* Non-inherited, "global" configuration data */
	unsigned log_console_fd;
	unsigned log_level;
	bool log_timestamp;
	char *log_file;

	bool whitelist_per_process_directories;
	bool whitelist_successful_bind;
	bool whitelist_unsupported_socket_families;

	enum abort_decision abort_decision;

	enum panic_decision panic_decision;
	int panic_exit_code;

	enum violation_decision violation_decision;
	int violation_exit_code;
	bool violation_raise_fail;
	bool violation_raise_safe;

	bool follow_fork;
	bool exit_wait_all;

	slist_t exec_kill_if_match;
	slist_t exec_resume_if_match;

	slist_t filter_exec;
	slist_t filter_read;
	slist_t filter_write;
	slist_t filter_network;
} config_t;

typedef struct {
	/* Eldest child */
	pid_t eldest;

	/* Exit code */
	int exit_code;

	/* Wait until the first execve() is successful to start sandboxing. */
	unsigned wait_execve;

	/* This is true if an access violation has occured, false otherwise. */
	bool violation;

	/* Program invocation name (for the child) */
	char *program_invocation_name;

	/* Callback table */
	struct pink_easy_callback_table callback_table;

	/* Tracing context */
	struct pink_easy_context *ctx;

	/* Global configuration */
	config_t config;
} sydbox_t;

typedef int (*sysfunc_t) (struct pink_easy_process *current, const char *name);

typedef struct {
	const char *name;
	sysfunc_t enter;
	sysfunc_t exit;
} sysentry_t;

typedef struct {
	unsigned index;

	bool at;
	bool decode_socketcall;
	bool resolv;
	enum create_mode create;

	bool safe;
	int deny_errno;

	bool whitelisting;
	slist_t *wblist;

	slist_t *filter;

	long *fd;
	char **abspath;
	struct pink_sockaddr **addr;
} sys_info_t;

/* Global variables */
extern sydbox_t *sydbox;

/* Global functions */
void die(int code, const char *fmt, ...) PINK_GCC_ATTR((noreturn, format (printf, 2, 3)));
void die_errno(int code, const char *fmt, ...) PINK_GCC_ATTR((noreturn, format (printf, 2, 3)));
void *xmalloc(size_t size) PINK_GCC_ATTR((malloc));
void *xcalloc(size_t nmemb, size_t size) PINK_GCC_ATTR((malloc));
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *src) PINK_GCC_ATTR((malloc));
char *xstrndup(const char *src, size_t n) PINK_GCC_ATTR((malloc));
int xasprintf(char **strp, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));
char *xgetcwd(void);

#define LOG_DEFAULT_PREFIX PACKAGE
#define LOG_DEFAULT_SUFFIX "\n"

void log_init(void);
void log_close(void);
void log_prefix(const char *p);
void log_suffix(const char *s);
void log_msg_va(unsigned level, const char *fmt, va_list ap) PINK_GCC_ATTR((format (printf, 2, 0)));
void log_msg(unsigned level, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));
#define fatal(...)	log_msg(0, __VA_ARGS__)
#define warning(...)	log_msg(1, __VA_ARGS__)
#define message(...)	log_msg(2, __VA_ARGS__)
#define info(...)	log_msg(3, __VA_ARGS__)
#define debug(...)	log_msg(4, __VA_ARGS__)
#define trace(...)	log_msg(5, __VA_ARGS__)

void abort_all(void);
int deny(struct pink_easy_process *current);
int restore(struct pink_easy_process *current);
int panic(struct pink_easy_process *current);
int violation(struct pink_easy_process *current, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));

int wildmatch_expand(const char *pattern, char ***buf);

sock_info_t *sock_info_xdup(sock_info_t *src);

int sock_match_expand(const char *src, char ***buf);
int sock_match_new(const char *src, sock_match_t **buf);
int sock_match_new_pink(const sock_info_t *src, sock_match_t **buf);
sock_match_t *sock_match_xdup(const sock_match_t *src);
int sock_match(const sock_match_t *haystack, const struct pink_sockaddr *needle);

int magic_set_panic_exit_code(const void *val, struct pink_easy_process *current);
int magic_set_violation_exit_code(const void *val, struct pink_easy_process *current);
int magic_set_violation_raise_fail(const void *val, struct pink_easy_process *current);
int magic_query_violation_raise_fail(struct pink_easy_process *current);
int magic_set_violation_raise_safe(const void *val, struct pink_easy_process *current);
int magic_query_violation_raise_safe(struct pink_easy_process *current);
int magic_set_trace_follow_fork(const void *val, struct pink_easy_process *current);
int magic_query_trace_follow_fork(struct pink_easy_process *current);
int magic_set_trace_exit_wait_all(const void *val, struct pink_easy_process *current);
int magic_query_trace_exit_wait_all(struct pink_easy_process *current);
int magic_set_whitelist_ppd(const void *val, struct pink_easy_process *current);
int magic_query_whitelist_ppd(struct pink_easy_process *current);
int magic_set_whitelist_sb(const void *val, struct pink_easy_process *current);
int magic_query_whitelist_sb(struct pink_easy_process *current);
int magic_set_whitelist_usf(const void *val, struct pink_easy_process *current);
int magic_query_whitelist_usf(struct pink_easy_process *current);
int magic_set_whitelist_exec(const void *val, struct pink_easy_process *current);
int magic_set_whitelist_read(const void *val, struct pink_easy_process *current);
int magic_set_whitelist_write(const void *val, struct pink_easy_process *current);
int magic_set_blacklist_exec(const void *val, struct pink_easy_process *current);
int magic_set_blacklist_read(const void *val, struct pink_easy_process *current);
int magic_set_blacklist_write(const void *val, struct pink_easy_process *current);
int magic_set_filter_exec(const void *val, struct pink_easy_process *current);
int magic_set_filter_read(const void *val, struct pink_easy_process *current);
int magic_set_filter_write(const void *val, struct pink_easy_process *current);
int magic_set_whitelist_network_bind(const void *val, struct pink_easy_process *current);
int magic_set_whitelist_network_connect(const void *val, struct pink_easy_process *current);
int magic_set_blacklist_network_bind(const void *val, struct pink_easy_process *current);
int magic_set_blacklist_network_connect(const void *val, struct pink_easy_process *current);
int magic_set_filter_network(const void *val, struct pink_easy_process *current);
int magic_set_abort_decision(const void *val, struct pink_easy_process *current);
int magic_set_panic_decision(const void *val, struct pink_easy_process *current);
int magic_set_violation_decision(const void *val, struct pink_easy_process *current);
int magic_set_trace_magic_lock(const void *val, struct pink_easy_process *current);
int magic_set_log_file(const void *val, struct pink_easy_process *current);
int magic_set_log_console_fd(const void *val, struct pink_easy_process *current);
int magic_set_log_level(const void *val, struct pink_easy_process *current);
int magic_set_log_timestamp(const void *val, struct pink_easy_process *current);
int magic_query_log_timestamp(struct pink_easy_process *current);
int magic_query_sandbox_exec(struct pink_easy_process *current);
int magic_query_sandbox_read(struct pink_easy_process *current);
int magic_query_sandbox_write(struct pink_easy_process *current);
int magic_query_sandbox_network(struct pink_easy_process *current);
int magic_set_sandbox_exec(const void *val, struct pink_easy_process *current);
int magic_set_sandbox_read(const void *val, struct pink_easy_process *current);
int magic_set_sandbox_write(const void *val, struct pink_easy_process *current);
int magic_set_sandbox_network(const void *val, struct pink_easy_process *current);
int magic_set_exec_kill_if_match(const void *val, struct pink_easy_process *current);
int magic_set_exec_resume_if_match(const void *val, struct pink_easy_process *current);

const char *magic_strerror(int error);
const char *magic_strkey(enum magic_key key);
unsigned magic_key_type(enum magic_key key);
unsigned magic_key_parent(enum magic_key key);
unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len);
int magic_cast(struct pink_easy_process *current, enum magic_key key, enum magic_type type, const void *val);
int magic_cast_string(struct pink_easy_process *current, const char *magic, int prefix);

void config_init(void);
void config_done(void);
void config_reset(void);
void config_parse_file(const char *filename) PINK_GCC_ATTR((nonnull(1)));
void config_parse_spec(const char *filename) PINK_GCC_ATTR((nonnull(1)));

void callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid, int maycreat, int resolve, char **res);
int box_match_path(const char *path, const slist_t *patterns, const char **match);
int box_check_path(struct pink_easy_process *current, const char *name, sys_info_t *info);
int box_check_sock(struct pink_easy_process *current, const char *name, sys_info_t *info);

int path_decode(struct pink_easy_process *current, unsigned ind, char **buf);
int path_prefix(struct pink_easy_process *current, unsigned ind, char **buf);

void systable_init(void);
void systable_free(void);
void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit);
const sysentry_t *systable_lookup(long no, enum pink_abi abi);

void sysinit(void);
int sysenter(struct pink_easy_process *current);
int sysexit(struct pink_easy_process *current);

int sys_chmod(struct pink_easy_process *current, const char *name);
int sys_fchmodat(struct pink_easy_process *current, const char *name);
int sys_chown(struct pink_easy_process *current, const char *name);
int sys_lchown(struct pink_easy_process *current, const char *name);
int sys_fchownat(struct pink_easy_process *current, const char *name);
int sys_open(struct pink_easy_process *current, const char *name);
int sys_openat(struct pink_easy_process *current, const char *name);
int sys_creat(struct pink_easy_process *current, const char *name);
int sys_close(struct pink_easy_process *current, const char *name);
int sys_mkdir(struct pink_easy_process *current, const char *name);
int sys_mkdirat(struct pink_easy_process *current, const char *name);
int sys_mknod(struct pink_easy_process *current, const char *name);
int sys_mknodat(struct pink_easy_process *current, const char *name);
int sys_rmdir(struct pink_easy_process *current, const char *name);
int sys_truncate(struct pink_easy_process *current, const char *name);
int sys_mount(struct pink_easy_process *current, const char *name);
int sys_umount(struct pink_easy_process *current, const char *name);
int sys_umount2(struct pink_easy_process *current, const char *name);
int sys_utime(struct pink_easy_process *current, const char *name);
int sys_utimes(struct pink_easy_process *current, const char *name);
int sys_utimensat(struct pink_easy_process *current, const char *name);
int sys_futimesat(struct pink_easy_process *current, const char *name);
int sys_unlink(struct pink_easy_process *current, const char *name);
int sys_unlinkat(struct pink_easy_process *current, const char *name);
int sys_link(struct pink_easy_process *current, const char *name);
int sys_linkat(struct pink_easy_process *current, const char *name);
int sys_rename(struct pink_easy_process *current, const char *name);
int sys_renameat(struct pink_easy_process *current, const char *name);
int sys_symlink(struct pink_easy_process *current, const char *name);
int sys_symlinkat(struct pink_easy_process *current, const char *name);
int sys_setxattr(struct pink_easy_process *current, const char *name);
int sys_lsetxattr(struct pink_easy_process *current, const char *name);
int sys_removexattr(struct pink_easy_process *current, const char *name);
int sys_lremovexattr(struct pink_easy_process *current, const char *name);

int sys_access(struct pink_easy_process *current, const char *name);
int sys_faccessat(struct pink_easy_process *current, const char *name);

int sys_dup(struct pink_easy_process *current, const char *name);
int sys_dup3(struct pink_easy_process *current, const char *name);
int sys_fcntl(struct pink_easy_process *current, const char *name);

int sys_execve(struct pink_easy_process *current, const char *name);
int sys_stat(struct pink_easy_process *current, const char *name);

int sys_socketcall(struct pink_easy_process *current, const char *name);
int sys_bind(struct pink_easy_process *current, const char *name);
int sys_connect(struct pink_easy_process *current, const char *name);
int sys_sendto(struct pink_easy_process *current, const char *name);
int sys_recvfrom(struct pink_easy_process *current, const char *name);
int sys_getsockname(struct pink_easy_process *current, const char *name);

int sysx_chdir(struct pink_easy_process *current, const char *name);
int sysx_close(struct pink_easy_process *current, const char *name);
int sysx_dup(struct pink_easy_process *current, const char *name);
int sysx_fcntl(struct pink_easy_process *current, const char *name);
int sysx_socketcall(struct pink_easy_process *current, const char *name);
int sysx_bind(struct pink_easy_process *current, const char *name);
int sysx_getsockname(struct pink_easy_process *current, const char *name);

static inline sandbox_t *box_current(struct pink_easy_process *current)
{
	proc_data_t *data;

	if (current) {
		data = pink_easy_process_get_userdata(current);
		return &data->config;
	}

	return &sydbox->config.child;
}

static inline void free_sock_info(void *data)
{
	sock_info_t *info = data;

	if (info->path)
		free(info->path);
	free(info->addr);
	free(info);
}

static inline void free_sock_match(void *data)
{
	sock_match_t *m = data;

	if (m->str)
		free(m->str);
	if (m->family == AF_UNIX && m->match.sa_un.path)
		free(m->match.sa_un.path);
	free(m);
}

static inline void free_sandbox(sandbox_t *box)
{
	struct snode *node;

	SLIST_FLUSH(node, &box->whitelist_exec, up, free);
	SLIST_FLUSH(node, &box->whitelist_read, up, free);
	SLIST_FLUSH(node, &box->whitelist_write, up, free);
	SLIST_FLUSH(node, &box->whitelist_network_bind, up, free_sock_match);
	SLIST_FLUSH(node, &box->whitelist_network_connect, up, free_sock_match);

	SLIST_FLUSH(node, &box->blacklist_exec, up, free);
	SLIST_FLUSH(node, &box->blacklist_read, up, free);
	SLIST_FLUSH(node, &box->blacklist_write, up, free);
	SLIST_FLUSH(node, &box->blacklist_network_bind, up, free_sock_match);
	SLIST_FLUSH(node, &box->blacklist_network_connect, up, free_sock_match);
}

static inline void free_proc(void *data)
{
	proc_data_t *p = data;

	if (!p)
		return;

	if (p->abspath)
		free(p->abspath);

	if (p->cwd)
		free(p->cwd);

	if (p->comm)
		free(p->comm);

	if (p->savebind)
		free_sock_info(p->savebind);

	/* Free the fd -> address mappings */
	for (int i = 0; i < p->sockmap->size; i++) {
		ht_int64_node_t *node = HT_NODE(p->sockmap, p->sockmap->nodes, i);
		if (node->data)
			free_sock_info(node->data);
	}
	hashtable_destroy(p->sockmap);

	/* Free the sandbox */
	free_sandbox(&p->config);

	/* Free the rest */
	free(p);
}

static inline void clear_proc(void *data)
{
	proc_data_t *p = data;

	p->deny = false;
	p->retval = 0;
	p->subcall = 0;
	for (unsigned i = 0; i < PINK_MAX_ARGS; i++)
		p->args[i] = 0;

	if (p->savebind)
		free_sock_info(p->savebind);
	p->savebind = NULL;
}

#define sandbox_exec_on(data)		(!!((data)->config.sandbox_exec == SANDBOX_ON))
#define sandbox_exec_off(data)		(!!((data)->config.sandbox_exec == SANDBOX_OFF))
#define sandbox_exec_deny(data)		(!!((data)->config.sandbox_exec == SANDBOX_DENY))

#define sandbox_read_on(data)		(!!((data)->config.sandbox_read == SANDBOX_ON))
#define sandbox_read_off(data)		(!!((data)->config.sandbox_read == SANDBOX_OFF))
#define sandbox_read_deny(data)		(!!((data)->config.sandbox_read == SANDBOX_DENY))

#define sandbox_write_on(data)		(!!((data)->config.sandbox_write == SANDBOX_ON))
#define sandbox_write_off(data)		(!!((data)->config.sandbox_write == SANDBOX_OFF))
#define sandbox_write_deny(data)	(!!((data)->config.sandbox_write == SANDBOX_DENY))

#define sandbox_network_on(data)	(!!((data)->config.sandbox_network == SANDBOX_ON))
#define sandbox_network_off(data)	(!!((data)->config.sandbox_network == SANDBOX_OFF))
#define sandbox_network_deny(data)	(!!((data)->config.sandbox_network == SANDBOX_DENY))

#endif /* !SYDBOX_GUARD_DEFS_H */
