#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox fchmodat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'fchmodat(AT_FDCWD, $file) returns ERRNO_0' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ERRNO_0 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success 'fchmodat($dir, $file) returns ERRNO_0' '
    f="$(file_uniq)" &&
    d="$(dir_uniq)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ERRNO_0 "$f" &&
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success SYMLINKS 'fchmodat(AT_FDCWD, $symlink) returns ERRNO_0' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ERRNO_0 "$l"
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success SYMLINKS 'fchmodat($dir, $symlink) returns ERRNO_0' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    d="$(dir_uniq)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    ln -sf "$f" "$d"/"$l" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ERRNO_0 "$l" &&
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success 'fchmodat(AT_FDCWD, NULL) returns EFAULT' '
    sydbox -- emily fchmodat -d cwd -m 000 -e EFAULT
'

test_expect_success 'fchmodat($dir, NULL) returns EFAULT' '
    d="$(dir_uniq)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e EFAULT
'

test_expect_success 'fchmodat($badfd, $file) returns EBADF' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    sydbox -- emily fchmodat -d null -m 000 -e EBADF "$f"
'

test_expect_success 'fchmodat($badfd, "") returns ENOENT' '
    sydbox -- emily fchmodat -d null -m 000 -e ENOENT ""
'

test_expect_success 'fchmodat(AT_FDCWD, "") returns ENOENT' '
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOENT ""
'

test_expect_success 'fchmodat($dir, "") returns ENOENT' '
    d="$(dir_uniq)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOENT ""
'

test_expect_success 'fchmodat(AT_FDCWD, $nofile) returns ENOENT' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOENT "$f"
'

test_expect_success 'fchmodat($dir, $nofile) returns ENOENT' '
    f="no-$(file_uniq)" &&
    d="$(dir_uniq)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOENT "$f"
'

test_expect_success 'fchmodat(AT_FDCWD, $noaccess/$file) returns EACCES' '
    d="no-access-$(dir_uniq)" &&
    f="$(file_uniq)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    test_when_finished "chmod 700 $d" && chmod 000 "$d" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e EACCES "$d"/"$f" &&
    chmod 700 "$d" &&
    test_path_is_readable "$d"/"$f" &&
    test_path_is_writable "$d"/"$f"
'

# TODO: emily limitation, not easy to test...
#test_expect_success 'fchmodat($noaccess, $file) returns EACCES' '
#    d="no-access-$(dir_uniq)" &&
#    f="$(file_uniq)" &&
#    mkdir "$d" &&
#    touch "$d"/"$f" &&
#    chmod 600 "$d"/"$f" &&
#    chmod 000 "$d" &&
#    sydbox -- emily fchmodat -d "$d" -m 000 -e EACCES "$f" &&
#    chmod 700 "$d" &&
#    test_path_is_readable "$d"/"$f" &&
#    test_path_is_writable "$d"/"$f" &&
#'

test_expect_success 'fchmodat(AT_FDCWD, $nodir/$file) returns ENOTDIR' '
    d="non-$(dir_uniq)" &&
    touch "$d" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOTDIR "$d"/foo
'

test_expect_success 'fchmodat($nodir, $file) returns ENOTDIR' '
    d="non-$(dir_uniq)" &&
    touch "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOTDIR "$d"/foo
'

test_expect_success SYMLINKS 'fchmodat(AT_FDCWD, $symlink-self) returns ELOOP' '
    l="self-$(link_uniq)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ELOOP "$l"
'

test_expect_success SYMLINKS 'fchmodat($dir, $symlink-self) returns ELOOP' '
    d="$(dir_uniq)" &&
    l="self-$(link_uniq)" &&
    mkdir "$d" &&
    (
        cd "$d" &&
        ln -sf "$l" "$l"
    ) &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ELOOP "$l"
'

test_expect_success SYMLINKS 'fchmodat(AT_FDCWD, $symlink-circular) returns ELOOP' '
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ELOOP "$l0"
'

test_expect_success SYMLINKS 'fchmodat($dir, $symlink-circular) returns ELOOP' '
    d="$(dir_uniq)" &&
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    mkdir "$d" &&
    (
        cd "$d"
        ln -sf "$l0" "$l1" &&
        ln -sf "$l1" "$l0"
    ) &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ELOOP "$l0"
'

test_expect_success 'deny fchmodat(-1, $abspath) with EPERM' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'deny fchmodat(AT_FDCWD, $file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'deny fchmodat(AT_FDCWD, $nofile)' '
    f="no-$(file_uniq)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success 'deny fchmodat(AT_FDCWD, $symlink-file)' '
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'deny fchmodat($fd, $file)' '
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'deny fchmodat($fd, $nofile)' '
    rm -f no"$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success SYMLINKS 'deny fchmodat($fd, $symlink-file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist fchmodat(-1, $abspath)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, $file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist fchmodat(AT_FDCWD, $nofile)' '
    f="no-$(file_uniq)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success SYMLINKS 'blacklist fchmodat(AT_FDCWD, $symlink-file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist fchmodat($fd, $file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'blacklist fchmodat($fd, $nofile)' '
    f="no-$(file_uniq)" &&
    rm -f no"$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success SYMLINKS 'blacklist fchmodat($fd, $symlink-file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success 'whitelist fchmodat(-1, $abspath)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success 'whitelist fchmodat(AT_FDCWD, $file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success SYMLINKS 'whitelist fchmodat(AT_FDCWD, $symlink-file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success 'whitelist fchmodat($fd, $file)' '
    f="$(file_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success SYMLINKS 'whitelist fchmodat($fd, $symlink-file)' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_done
