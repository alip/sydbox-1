#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox fchmodat()'
. ./test-lib.sh

test_expect_success setup '
    touch file1 &&
    touch file2 &&
    touch file3 &&
    touch file4 &&
    touch file5 &&
    touch file6 &&
    touch file7 &&
    touch file8 &&
    touch file9 &&
    touch file10 &&
    touch file11 &&
    touch file12
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file4 symlink-file4 &&
    ln -sf file6 symlink-file6 &&
    ln -sf file8 symlink-file8 &&
    ln -sf file10 symlink-file10 &&
    ln -sf file12 symlink-file12
'

test_expect_success 'deny fchmodat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily fchmodat -e EFAULT -d cwd
'

test_expect_success 'deny fchmodat(-1) with EBADF' '
    sydbox -- emily fchmodat -e EBADF -d null -m 000 file0-non-existant
'

test_expect_success 'deny fchmodat(AT_FDCWD, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 file1 &&
    test_path_is_readable file1 &&
    test_path_is_writable file1
'

test_expect_success 'deny fchmodat(AT_FDCWD, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 file-non-existant
'

test_expect_success 'deny fchmodat(AT_FDCWD, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 symlink-file2 &&
    test_path_is_readable file2 &&
    test_path_is_writable file2
'

test_expect_success 'deny fchmodat(fd, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 file3 &&
    test_path_is_readable file3 &&
    test_path_is_writable file3
'

test_expect_success 'deny fchmodat(fd, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 file-non-existant
'

test_expect_success 'deny fchmodat(fd, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 symlink-file4 &&
    test_path_is_readable file4 &&
    test_path_is_writable file4
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 file5 &&
    test_path_is_readable file5 &&
    test_path_is_writable file5
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 file-non-existant
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 symlink-file6 &&
    test_path_is_readable file6 &&
    test_path_is_writable file6
'

test_expect_success 'blacklist fchmodat(fd, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 file7 &&
    test_path_is_readable file7 &&
    test_path_is_writable file7
'

test_expect_success 'blacklist fchmodat(fd, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 file-non-existant
'

test_expect_success 'blacklist fchmodat(fd, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 symlink-file8 &&
    test_path_is_readable file8 &&
    test_path_is_writable file8
'

test_expect_success 'whitelist fchmodat(AT_FDCWD, ...)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 file9 &&
    test_path_is_not_readable file9 &&
    test_path_is_not_writable file9
'

test_expect_success SYMLINKS 'whitelist fchmodat(AT_FDCWD) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 symlink-file10 &&
    test_path_is_not_readable file10 &&
    test_path_is_not_writable file10
'

test_expect_success 'whitelist fchmodat(fd, ...)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 file11 &&
    test_path_is_not_readable file11 &&
    test_path_is_not_writable file11
'

test_expect_success SYMLINKS 'whitelist fchmodat(fd, ...) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 symlink-file12 &&
    test_path_is_not_readable file12 &&
    test_path_is_not_writable file12
'

test_done
