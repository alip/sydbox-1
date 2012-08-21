/*
 * sydbox/file.h
 *
 * File related utilities
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is
 *   Copyright 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef FILE_H
#define FILE_H 1

char *truncate_nl(char *s);

int basename_alloc(const char *path, char **buf);
int readlink_alloc(const char *path, char **buf);
int read_one_line_file(const char *fn, char **line);

#endif /* !FILE_H */
