#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox open(2)'
. ./test-lib.sh

test_expect_success 'deny open(NULL) with EFAULT' '
    sydbox -- emily open -e EFAULT
'

test_expect_success 'deny open(file, O_RDONLY|O_DIRECTORY) with ENOTDIR' '
    touch file.$test_count
    sydbox -- emily open -e ENOTDIR -m rdonly -D file.$test_count
'

test_expect_success SYMLINKS 'deny open(symlink-file, O_RDONLY|O_NOFOLLOW) with ELOOP' '
    touch file.$test_count
    ln -sf file.$test_count link.$test_count
    sydbox -- emily open -e ELOOP -m rdonly -F link.$test_count
'

test_expect_success 'whitelist O_RDONLY' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly file.$test_count
'

test_expect_success SYMLINKS 'whitelist O_RDONLY for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly link.$test_count
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -cx nofile.$test_count rdonly-creat-excl &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx file.$test_count
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_WRONLY' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny O_WRONLY for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ENOENT -m wronly nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny O_WRONLY for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny O_WRONLY|O_CREAT' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_WRONLY|O_CREAT for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -cx nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m wronly -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'whitelist O_WRONLY' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist O_WRONLY|O_CREAT' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist O_WRONLY|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx file.$test_count
'

test_expect_success 'deny O_RDWR' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny O_RDWR|O_CREAT' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdwr -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'whitelist O_RDWR' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist O_RDWR|O_CREAT' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist O_RDWR|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist O_RDWR|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdwr -cx file.$test_count
'

test_expect_success 'blacklist O_RDONLY|O_CREAT' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist O_RDONLY|O_CREAT for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_RDONLY|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_RDONLY|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx file.$test_count
'

test_expect_success SYMLINKS 'blacklist O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_WRONLY' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist O_WRONLY for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e ENOENT -m wronly nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist O_WRONLY for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist O_WRONLY|O_CREAT' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_WRONLY|O_CREAT for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist O_WRONLY|O_CREAT for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist O_WRONLY|O_CREAT for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_WRONLY|O_CREAT|O_EXCL' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_done
