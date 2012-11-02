#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox fchownat()'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny fchownat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily fchownat -e EFAULT -d cwd
'

test_expect_success 'deny fchownat(-1) with EBADF' '
    sydbox -- emily fchownat -e EBADF -d null nofile.$test_count
'

test_expect_success 'deny fchownat(-1, $abspath) with EPERM' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d null "$HOME_RESOLVED"/file.$test_count
'

test_expect_success 'deny fchownat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd file.$test_count
'

test_expect_success 'deny fchownat(AT_FDCWD, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd nofile.$test_count
'

test_expect_success SYMLINKS 'deny fchownat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd link.$test_count
'

test_expect_success 'deny fchownat($fd, $file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d "$HOME" file.$test_count
'

test_expect_success 'deny fchownat($fd, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd nofile.$test_count
'

test_expect_success SYMLINKS 'deny fchownat($fd, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd link.$test_count
'

test_expect_success 'blacklist fchownat(-1, $abspath)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d null "$HOME_RESOLVED"/file.$test_count
'

test_expect_success 'blacklist fchownat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd file.$test_count
'

test_expect_success 'blacklist fchownat(AT_FDCWD, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist fchownat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd link.$test_count
'

test_expect_success 'blacklist fchownat($fd, $file)' '
    touch file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d "$HOME" file.$test_count
'

test_expect_success 'blacklist fchownat($fd, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist fchownat($fd, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd link.$test_count
'

test_expect_success 'whitelist fchownat(-1, $abspath)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d null "$HOME_RESOLVED"/file.$test_count
'

test_expect_success 'whitelist fchownat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd file.$test_count
'

test_expect_success SYMLINKS 'whitelist fchownat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd link.$test_count
'

test_expect_success 'whitelist fchownat($fd, $file)' '
    touch file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" file.$test_count
'

test_expect_success SYMLINKS 'whitelist fchownat($fd, $symlink-file)' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" link.$test_count
'

test_done
