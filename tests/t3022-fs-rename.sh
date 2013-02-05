#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox rename(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'rename($oldpath, $newpath) returns ERRNO_0' '
    old="$(file_uniq)" &&
    new="$(file_uniq)" &&
    touch "$old" &&
    sydbox -- emily rename -e ERRNO_0 "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_file "$new"
'

test_expect_success 'rename(NULL, NULL) returns EFAULT' '
    sydbox -- emily rename -e EFAULT
'

test_expect_success 'rename($oldpath, $oldpath/$newpath) returns EINVAL' '
    old="$(dir_uniq)" &&
    mkdir "$old" &&
    sydbox -- emily rename -e EINVAL "$old" "$old"/new &&
    test_path_is_dir "$old" &&
    test_path_is_missing "$old"/new
'

test_expect_success 'rename($file, $dir) returns EISDIR' '
    f="$(file_uniq)" &&
    d="$(dir_uniq)" &&
    touch "$f" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$f" "$d" &&
    test_path_is_file "$f" &&
    test_path_is_dir "$d"
'

test_expect_success SYMLINKS 'rename($symlink, $dir) returns EISDIR' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    d="$(dir_uniq)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$l" "$d" &&
    test_path_is_symlink "$l" &&
    test_path_is_dir "$d"
'

test_expect_success SYMLINKS 'rename($symlink-self, $dir) returns EISDIR' '
    d="$(dir_uniq)" &&
    l="self-$(link_uniq)" &&
    ln -sf "$l" "$l" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$l" "$d" &&
    test_path_is_symlink "$l" &&
    test_path_is_dir "$d"
'

test_expect_success SYMLINKS 'rename($symlink-self/$file, $newfile) returns ELOOP' '
    f="$(file_uniq)" &&
    l="self-$(link_uniq)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ELOOP "$l"/file "$f" &&
    test_path_is_missing "$f"
'

test_expect_success SYMLINKS 'rename($file, $symlink-self/$newfile returns ELOOP' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ELOOP "$f" "$l"/newfile &&
    test_path_is_file "$f"
'

test_expect_success SYMLINKS 'rename($symlink-circular/$file, $newfile) returns ELOOP' '
    f="$(file_uniq)" &&
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ELOOP "$l0"/file "$f" &&
    test_path_is_missing "$f"
'

test_expect_success SYMLINKS 'rename($file, $symlink-circular/$newfile) returns ELOOP' '
    f="$(file_uniq)" &&
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    touch "$f" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ELOOP "$f" "$l0"/newfile &&
    test_path_is_file "$f"
'

test_expect_success SYMLINKS 'rename($symlink-self, $newsymlink) returns ERRNO_0' '
    old="self-$(link_uniq)" &&
    new="self-$(link_uniq)" &&
    ln -sf "$old" "$old" &&
    sydbox -- emily rename -e ERRNO_0 "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_symlink "$new"
'

test_expect_success SYMLINKS 'rename($file, $symlink-self) returns ERRNO_0' '
    f="$(file_uniq)" &&
    l="$(link_uniq)" &&
    touch "$f" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ERRNO_0 "$f" "$l" &&
    test_path_is_missing "$f" &&
    test_path_is_file "$l"
'

test_expect_success SYMLINKS 'rename($symlink-circular, $newsymlink) returns ERRNO_0' '
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    new="loop-new-$(link_uniq)"
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ERRNO_0 "$l0" "$new" &&
    test_path_is_missing "$l0" &&
    test_path_is_symlink "$l1" &&
    test_path_is_symlink "$new"
'

test_expect_success SYMLINKS 'rename($file, $symlink-circular) returns ERRNO_0' '
    f="$(file_uniq)" &&
    l0="loop0-$(link_uniq)" &&
    l1="loop1-$(link_uniq)" &&
    touch "$f" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "l0" &&
    sydbox -- emily rename -e ERRNO_0 "$f" "$l0" &&
    test_path_is_missing "$f" &&
    test_path_is_file "$l0" &&
    test_path_is_symlink "$l1"
'

test_expect_success 'rename($nofile, $newfile) returns ENOENT' '
    old="no-$(file_uniq)" &&
    new="new-$(file_uniq)" &&
    rm -f "$old" &&
    rm -f "$new" &&
    sydbox -- emily rename -e ENOENT "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_missing "$new"
'

test_expect_success 'rename($file, $nodir/$newfile) returns ENOENT' '
    f="$(file_uniq)" &&
    d="$(dir_uniq)" &&
    touch "$f" &&
    rm -f "$d" &&
    sydbox -- emily rename -e ENOENT "$f" "$d"/newfile &&
    test_path_is_file "$f" &&
    test_path_is_missing "$d"/newfile &&
    test_path_is_missing "$d"
'

test_expect_success 'rename("", $newfile) returns ENOENT' '
    f="$(file_uniq)" &&
    sydbox -- emily rename -e ENOENT "" "$f" &&
    test_path_is_missing "$f"
'

test_expect_success 'rename($file, "") returns ENOENT' '
    f="$(file_uniq)" &&
    touch "$f" &&
    sydbox -- emily rename -e ENOENT "$f" "" &&
    test_path_is_file "$f"
'

test_expect_success 'rename("", "") returns ENOENT' '
    sydbox -- emily rename -e ENOENT "" ""
'

test_expect_success 'rename($olddir, $newfile) returns ENOTDIR' '
    d="$(dir_uniq)" &&
    f="$(file_uniq)" &&
    mkdir "$d" &&
    touch "$f" &&
    sydbox -- emily rename -e ENOTDIR "$d" "$f" &&
    test_path_is_dir "$d" &&
    test_path_is_file "$f"
'

test_expect_success 'rename($olddir, $new-nonempty-dir) returns ENOTEMPTY' '
    d0="$(dir_uniq)" &&
    d1="$(dir_uniq)" &&
    mkdir "$d0" &&
    mkdir "$d1" &&
    touch "$d1"/file &&
    sydbox -- emily rename -e ENOTEMPTY "$d0" "$d1" &&
    test_path_is_dir "$d0" &&
    test_path_is_dir "$d1" &&
    test_path_is_file "$d1"/file
'

test_done
