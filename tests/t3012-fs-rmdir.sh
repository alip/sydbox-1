#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox rmdir(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'rmdir($empty-dir) returns ERRNO_0' '
    mkdir empty-dir.$test_count &&
    sydbox -- emily rmdir -e ERRNO_0 empty-dir.$test_count &&
    test_path_is_missing empty-dir.$test_count
'

test_expect_success 'rmdir($noaccess/$empty-dir) returns EACCES' '
    mkdir noaccess.$test_count &&
    mkdir noaccess.$test_count/empty-dir.$test_count &&
    chmod 700 noaccess.$test_count/empty-dir.$test_count &&
    chmod 000 noaccess.$test_count &&
    sydbox -- emily rmdir -e EACCES noaccess.$test_count/empty-dir.$test_count &&
    chmod 700 noaccess.$test_count &&
    test_path_is_dir noaccess.$test_count/empty-dir.$test_count
'

test_expect_success 'rmdir(NULL) returns EFAULT' '
    sydbox -- emily rmdir -e EFAULT
'

test_expect_success 'rmdir($empty-dir/.) returns EINVAL' '
    mkdir empty-dir.$test_count &&
    sydbox -- emily rmdir -e EINVAL empty-dir.$test_count/. &&
    test_path_is_dir empty-dir.$test_count
'

test_expect_success SYMLINKS 'rmdir($symlink-self/foo) returns ELOOP' '
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily rmdir -e ELOOP self-link.$test_count/foo
'

test_expect_success SYMLINKS 'rmdir($symlink-circular/foo) returns ELOOP' '
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily rmdir -e ELOOP loop0.$test_count/foo
'

test_expect_success 'rmdir($nodir) returns ENOENT' '
    rm -f nodir.$test_count
    sydbox -- emily rmdir -e ENOENT nodir.$test_count
'

test_expect_success 'rmdir($notdir) returns ENOTDIR' '
    touch file.$test_count &&
    sydbox -- emily rmdir -e ENOTDIR file.$test_count &&
    test_path_is_file file.$test_count
'

test_expect_success SYMLINKS 'rmdir($symlink-dangling) returns ENOTDIR' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count nolink.$test_count &&
    sydbox -- emily rmdir -e ENOTDIR nolink.$test_count &&
    test_path_is_symlink nolink.$test_count
'

test_expect_success 'rmdir($not-empty-dir) returns ENOTEMPTY' '
    mkdir dir.$test_count &&
    touch dir.$test_count/file.$test_count &&
    sydbox -- emily rmdir -e ENOTEMPTY dir.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_failure 'deny rmdir()' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM dir.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_failure 'deny rmdir() for non-existant directory' '
    rm -fr nodir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM nodir.$test_count
'

test_expect_failure 'whitelist rmdir()' '
    mkdir dir.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e ERRNO_0 dir.$test_count &&
    test_path_is_missing dir.$test_count
'

test_expect_failure 'blacklist rmdir()' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM dir.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_failure 'blacklist rmdir() for non-existant directory' '
    rm -fr nodir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM nodir.$test_count
'

test_done
