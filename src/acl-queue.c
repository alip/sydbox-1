/*
 * sydbox/acl-queue.c
 *
 * ACL queue for sydbox based on TAILQ from <sys/queue.h>
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "acl-queue.h"

#include <stdbool.h>
#include <errno.h>

#include "xfunc.h"
#include "pathmatch.h"
#include "sockmatch.h"

unsigned acl_pathmatch(enum acl_action defaction, const aclq_t *aclq,
		       const void *needle, struct acl_node **match)
{
	struct acl_node *node;
	const char *path = needle;

	if (!aclq || !needle)
		goto out;

	ACLQ_FOREACH(node, aclq) {
		if (pathmatch(node->match, path)) {
			if (match)
				*match = node;
			return node->action | ACL_MATCH;
		}
	}

out:
	if (match)
		*match = NULL;
	return defaction | ACL_NOMATCH;
}

unsigned acl_sockmatch(enum acl_action defaction, const aclq_t *aclq,
		       const void *needle, struct acl_node **match)
{
	struct acl_node *node;
	const struct pink_sockaddr *psa = needle;

	if (!aclq || !needle)
		goto out;

	ACLQ_FOREACH(node, aclq) {
		if (sockmatch(node->match, psa)) {
			if (match)
				*match = node;
			return node->action | ACL_MATCH;
		}
	}

out:
	if (match)
		*match = NULL;
	return defaction | ACL_NOMATCH;
}

unsigned acl_sockmatch_saun(enum acl_action defaction, const aclq_t *aclq,
			    const void *needle, struct acl_node **match)
{
	struct acl_node *node;
	struct sockmatch *m;
	const char *abspath = needle;

	if (!aclq || !needle)
		goto out;

	ACLQ_FOREACH(node, aclq) {
		m = node->match;
		if (m->family != AF_UNIX || m->addr.sa_un.abstract)
			continue;
		if (pathmatch(m->addr.sa_un.path, abspath)) {
			if (match)
				*match = node;
			return node->action | ACL_MATCH;
		}
	}

out:
	if (match)
		*match = NULL;
	return defaction | ACL_NOMATCH;
}

bool acl_match_path(enum acl_action defaction, const aclq_t *aclq,
		    const char *path, const char **match)
{
	unsigned r;
	struct acl_node *node;

	if (!aclq || !path)
		return false;

	r = acl_pathmatch(defaction, aclq, path, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

bool acl_match_sock(enum acl_action defaction, const aclq_t *aclq,
		    const struct pink_sockaddr *psa, struct sockmatch **match)
{
	unsigned r;
	struct acl_node *node;

	if (!aclq || !psa)
		return false;

	r = acl_sockmatch(defaction, aclq, psa, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

bool acl_match_saun(enum acl_action defaction, const aclq_t *aclq,
		    const char *abspath, struct sockmatch **match)
{
	enum acl_action r;
	struct acl_node *node;

	if (!aclq || !abspath)
		return false;

	r = acl_sockmatch_saun(defaction, aclq, abspath, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

int acl_append_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand path pattern */
	c = f = pathmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		node = xmalloc(sizeof(struct acl_node));
		node->action = action;
		node->match = xstrdup(list[c]);
		ACLQ_INSERT_TAIL(aclq, node);
	}

	for (; f > 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

int acl_remove_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand path pattern */
	c = f = pathmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		struct acl_node *tvar;
		ACLQ_FOREACH_SAFE(node, aclq, tvar) {
			if (node->action == action && streq(node->match, list[c])) {
				ACLQ_REMOVE(aclq, node);
				free(node->match);
				free(node);
				break;
			}
		}
	}

	for (; f > 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

int acl_append_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int r;
	int c, f;
	char **list;
	struct sockmatch *match;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand network alias */
	r = 0;
	c = f = sockmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		errno = 0;
		if ((r = sockmatch_parse(list[c], &match)) < 0) {
			r = -errno;
			goto out;
		} else if (errno == EAFNOSUPPORT) {
			/* IPv6 support disabled? */
			r = -errno;
			goto out;
		}
		node = xmalloc(sizeof(struct acl_node));
		node->action = action;
		node->match = match;
		ACLQ_INSERT_TAIL(aclq, node);
	}

out:
	for (; f > 0; f--)
		free(list[f]);
	free(list);

	return r;
}

int acl_remove_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list;
	struct sockmatch *match;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand network alias */
	c = f = sockmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		struct acl_node *tvar;
		ACLQ_FOREACH_SAFE(node, aclq, tvar) {
			match = node->match;
			if (match->str && streq(match->str, pattern)) {
				ACLQ_REMOVE(aclq, node);
				free_sockmatch(match);
				free(node);
				break;
			}
		}
	}

	for (; f > 0; f--)
		free(list[f]);
	free(list);

	return 0;
}
