#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox openat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny openat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily openat -e EFAULT -d cwd
'

test_expect_success 'deny openat(-1) with EBADF' '
    rm -f nofile.$test_count &&
    sydbox -- emily openat -e EBADF -d null -m rdonly nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, file, O_RDONLY|O_DIRECTORY) with ENOTDIR' '
    touch file.$test_count
    sydbox -- emily openat -e ENOTDIR -m rdonly -D -d cwd file.$test_count
'

test_expect_success SYMLINKS 'deny open(AT_FDCWD, symlink-file, O_RDONLY|O_NOFOLLOW) with ELOOP' '
    touch file.$test_count
    ln -sf file.$test_count link.$test_count
    sydbox -- emily openat -e ELOOP -m rdonly -F -d cwd link.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_RDONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d null "$HOME_RESOLVED"/file.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd file.$test_count
'

test_expect_success SYMLINKS 'whitelist openat(AT_FDCWD, $path, O_RDONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd link.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_RDONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" file.$test_count
'

test_expect_success SYMLINKS 'whitelist openat(fd, $path, O_RDONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" link.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx file.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx file.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx file.$test_count
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null "$HOME_RESOLVED"/file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d cwd nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY) for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d "$HOME" nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null -c "$HOME_RESOLVED"/nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT for existing file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT for existing file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null -cx "$HOME_RESOLVED"/nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -cx nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx nofile.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_WRONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null "$HOME_RESOLVED"/file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_RDWR)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null "$HOME_RESOLVED"/file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDWR)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(-1, $abspath, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(-1, $path, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_RDWR)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null "$HOME_RESOLVED"/file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" file.$test_count "3" &&
    test_path_is_non_empty file.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT)' '
    rm -f nofile.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -c nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(-1, $abspath, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx file.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -cx nofile.$test_count &&
    test_path_is_file nofile.$test_count
'

test_expect_success 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx file.$test_count
'

test_expect_success 'blacklist openat(-1, $abspath, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(-1, $abspath, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx link.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(-1, $abspath, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null "$HOME_RESOLVED"/file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d cwd nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY) for non-existant file' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d "$HOME" nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null -c "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c link.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c link.$test_count "3" &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null -cx "$HOME_RESOLVED"/nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx nofile.$test_count &&
    test_path_is_missing nofile.$test_count
'

test_expect_success 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx file.$test_count "3" &&
    test_path_is_empty file.$test_count
'

test_done
