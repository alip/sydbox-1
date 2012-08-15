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
#include "sys-check.h"
#include "sydbox-conf.h"
#include "sydbox-magic.h"

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
	pink_regs_t regs;

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
	bool match_case_sensitive;
	enum no_wildcard_mode match_no_wildcard;

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
	bool trace_interrupt;
	bool use_seccomp;

	char *log_file;

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

	/* Wait for initial execve() to start sandboxing */
	bool wait_execve;

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

void cont_all(void);
void abort_all(int fatal_sig);
int deny(struct pink_easy_process *current, int err_no);
int restore(struct pink_easy_process *current);
int panic(struct pink_easy_process *current);
int violation(struct pink_easy_process *current, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));

int wildmatch_sydbox(const char *pattern, const char *text);
int wildmatch_expand(const char *pattern, char ***buf);

sock_info_t *sock_info_xdup(sock_info_t *src);

int sock_match_expand(const char *src, char ***buf);
int sock_match_new(const char *src, sock_match_t **buf);
int sock_match_new_pink(const sock_info_t *src, sock_match_t **buf);
sock_match_t *sock_match_xdup(const sock_match_t *src);
int sock_match(const sock_match_t *haystack, const struct pink_sockaddr *needle);

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

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		enum file_exist_mode file_mode, bool no_resolve, char **res);
int box_match_path(const char *path, const slist_t *patterns, const char **match);
int box_check_path(struct pink_easy_process *current, const char *name, sysinfo_t *info);
int box_check_socket(struct pink_easy_process *current, const char *name, sysinfo_t *info);

int path_decode(struct pink_easy_process *current, unsigned ind, char **buf);
int path_prefix(struct pink_easy_process *current, unsigned ind, char **buf);

void systable_init(void);
void systable_free(void);
void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit);
const sysentry_t *systable_lookup(long no, enum pink_abi abi);

size_t syscall_entries_max(void);
void sysinit(void);
int sysinit_seccomp(void);
int sysenter(struct pink_easy_process *current);
int sysexit(struct pink_easy_process *current);

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

#endif /* !SYDBOX_GUARD_DEFS_H */
