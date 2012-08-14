#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox fchownat()'
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

test_expect_success 'deny fchownat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily fchownat -e EFAULT -d cwd
'

test_expect_success 'deny fchownat(-1) with EBADF' '
    sydbox -- emily fchownat -e EBADF -d null file0-non-existant
'

test_expect_success 'deny fchownat(AT_FDCWD, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd file1
'

test_expect_success 'deny fchownat(AT_FDCWD, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd file-non-existant
'

test_expect_success 'deny fchownat(AT_FDCWD, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd symlink-file2
'

test_expect_success 'deny fchownat(fd, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d "$HOME" file3
'

test_expect_success 'deny fchownat(fd, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd file-non-existant
'

test_expect_success 'deny fchownat(fd, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd symlink-file4
'

test_expect_success 'blacklist fchownat(AT_FDCWD, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd file5
'

test_expect_success 'blacklist fchownat(AT_FDCWD, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd file-non-existant
'

test_expect_success 'blacklist fchownat(AT_FDCWD, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd symlink-file6
'

test_expect_success 'blacklist fchownat(fd, ...)' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d "$HOME" file7
'

test_expect_success 'blacklist fchownat(fd, ...) for non-existant file' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd file-non-existant
'

test_expect_success 'blacklist fchownat(fd, ...) for symbolic link' '
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd symlink-file8
'

test_expect_success 'whitelist fchownat(AT_FDCWD, ...)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd file9
'

test_expect_success SYMLINKS 'whitelist fchownat(AT_FDCWD) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd symlink-file10
'

test_expect_success 'whitelist fchownat(fd, ...)' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" file11
'

test_expect_success SYMLINKS 'whitelist fchownat(fd, ...) for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" symlink-file12
'

test_done
