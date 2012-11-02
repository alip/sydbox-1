#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox fchmodat()'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'deny fchmodat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily fchmodat -e EFAULT -d cwd
'

test_expect_success 'deny fchmodat(-1) with EBADF' '
    rm -f nofile.$test_count &&
    sydbox -- emily fchmodat -e EBADF -d null -m 000 nofile.$test_count
'

test_expect_success 'deny fchmodat(-1, $abspath) with EPERM' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'deny fchmodat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'deny fchmodat(AT_FDCWD, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 nofile.$test_count
'

test_expect_success 'deny fchmodat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'deny fchmodat($fd, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'deny fchmodat($fd, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'deny fchmodat($fd, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist fchmodat(-1, $abspath)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, $nofile)' '
    rm -f nofile.$test_count
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist fchmodat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist fchmodat($fd, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 file.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'blacklist fchmodat($fd, $nofile)' '
    rm -f nofile.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 nofile.$test_count
'

test_expect_success SYMLINKS 'blacklist fchmodat($fd, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 link.$test_count &&
    test_path_is_readable file.$test_count &&
    test_path_is_writable file.$test_count
'

test_expect_success 'whitelist fchmodat(-1, $abspath)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d null -m 000 "$HOME_RESOLVED"/file.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success 'whitelist fchmodat(AT_FDCWD, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 file.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success SYMLINKS 'whitelist fchmodat(AT_FDCWD, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 link.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success 'whitelist fchmodat($fd, $file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 file.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_expect_success SYMLINKS 'whitelist fchmodat($fd, $symlink-file)' '
    touch file.$test_count &&
    chmod 600 file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 link.$test_count &&
    test_path_is_not_readable file.$test_count &&
    test_path_is_not_writable file.$test_count
'

test_done
