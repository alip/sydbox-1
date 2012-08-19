/*
 * sydbox/sockmatch.h
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef SOCKMATCH_H
#define SOCKMATCH_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <pinktrace/pink.h>

#define MATCH_UNIX	"unix:"
#define MATCH_UNIX_ABS	"unix-abstract:"
#define MATCH_INET	"inet:"
#define MATCH_INET6	"inet6:"

#define ALIAS_LOOPBACK	"LOOPBACK@"
#define ALIAS_LOCAL	"LOCAL@"
#define ALIAS_LOCAL6	"LOCAL6@"
#define ALIAS_LOOPBACK6	"LOOPBACK6@"

struct sockinfo {
	char *path; /* resolved UNIX socket address */
	struct pink_sockaddr *addr;
};

struct sockmatch {
	/* The actual pattern, useful for removals */
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
	} addr;
};

extern struct sockinfo *sockinfo_xdup(struct sockinfo *src);
extern struct sockmatch *sockmatch_xdup(const struct sockmatch *src);

/* Expand network aliases and unix wildmatch patterns */
extern int sockmatch_expand(const char *src, char ***buf);

extern struct sockmatch *sockmatch_new(const struct sockinfo *src);
extern int sockmatch_parse(const char *src, struct sockmatch **buf);

extern int sockmatch(const struct sockmatch *haystack,
		     const struct pink_sockaddr *needle);

#define path_abstract(path) ((path)[0] == '\0' && (path)[1] != '\0')

static inline void free_sockinfo(void *data)
{
	struct sockinfo *info = data;

	if (info->path)
		free(info->path);
	free(info->addr);
	free(info);
}

static inline void free_sockmatch(void *data)
{
	struct sockmatch *match = data;

	if (match->str)
		free(match->str);
	if (match->family == AF_UNIX && match->addr.sa_un.path)
		free(match->addr.sa_un.path);
	free(match);
}

#endif
