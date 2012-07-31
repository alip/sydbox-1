/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
 *   Copyright (C) 2010-2012 Lennart Poettering
 *   Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef PATH_H
#define PATH_H 1

int path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);
char *path_kill_slashes(char *path);

#endif /* !PATH_H */
