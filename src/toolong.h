/*
 * sydbox/toolong.h
 *
 * Path (longer than PATH_MAX) handling
 *
 * Copyright (c) 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#ifndef TOOLONG_H
#define TOOLONG_H

int chdir_long(char *dir);
char *getcwd_long(void);

#endif
