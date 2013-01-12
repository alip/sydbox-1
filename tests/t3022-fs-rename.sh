#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox rename(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success 'rename($oldpath, $newpath) returns ERRNO_0' '
    touch oldpath.$test_count &&
    sydbox -- emily rename -e ERRNO_0 oldpath.$test_count newpath.$test_count &&
    test_path_is_missing old_path.$test_count &&
    test_path_is_file newpath.$test_count
'

test_expect_success 'rename(NULL, NULL) returns EFAULT' '
    sydbox -- emily rename -e EFAULT
'

test_expect_success 'rename($oldpath, $oldpath/$newpath) returns EINVAL' '
    mkdir oldpath.$test_count &&
    sydbox -- emily rename -e EINVAL oldpath.$test_count oldpath.$test_count/newpath.$test_count &&
    test_path_is_dir oldpath.$test_count &&
    test_path_is_missing oldpath.$test_count/newpath.$test_count
'

test_expect_success 'rename($file, $dir) returns EISDIR' '
    touch file.$test_count &&
    mkdir dir.$test_count &&
    sydbox -- emily rename -e EISDIR file.$test_count dir.$test_count &&
    test_path_is_file file.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_success SYMLINKS 'rename($symlink, $dir) returns EISDIR' '
    touch file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    mkdir dir.$test_count &&
    sydbox -- emily rename -e EISDIR link.$test_count dir.$test_count &&
    test_path_is_symlink link.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_success SYMLINKS 'rename($symlink-self, $dir) returns EISDIR' '
    ln -sf self-link.$test_count self-link.$test_count &&
    mkdir dir.$test_count &&
    sydbox -- emily rename -e EISDIR self-link.$test_count dir.$test_count &&
    test_path_is_symlink self-link.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_success SYMLINKS 'rename($symlink-self/$file, $newfile) returns ELOOP' '
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily rename -e ELOOP self-link.$test_count/file newfile.$test_count &&
    test_path_is_missing newfile.$test_count
'

test_expect_success SYMLINKS 'rename($file, $symlink-self/$newfile returns ELOOP' '
    touch file.$test_count &&
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily rename -e ELOOP file.$test_count self-link.$test_count/newfile &&
    test_path_is_file file.$test_count
'

test_expect_success SYMLINKS 'rename($symlink-circular/$file, $newfile) returns ELOOP' '
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily rename -e ELOOP loop0.$test_count/file newfile.$test_count &&
    test_path_is_missing newfile.$test_count
'

test_expect_success SYMLINKS 'rename($file, $symlink-circular/$newfile) returns ELOOP' '
    touch file.$test_count &&
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily rename -e ELOOP file.$test_count loop0.$test_count/newfile &&
    test_path_is_file file.$test_count
'

test_expect_success SYMLINKS 'rename($symlink-self, $newsymlink) returns ERRNO_0' '
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily rename -e ERRNO_0 self-link.$test_count newlink.$test_count &&
    test_path_is_missing self-link.$test_count &&
    test_path_is_symlink newlink.$test_count
'

test_expect_success SYMLINKS 'rename($file, $symlink-self) returns ERRNO_0' '
    touch file.$test_count &&
    ln -sf self-link.$test_count self-link.$test_count &&
    sydbox -- emily rename -e ERRNO_0 file.$test_count self-link.$test_count &&
    test_path_is_missing file.$test_count &&
    test_path_is_file self-link.$test_count
'

test_expect_success SYMLINKS 'rename($symlink-circular, $newsymlink) returns ERRNO_0' '
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily rename -e ERRNO_0 loop0.$test_count newlink.$test_count &&
    test_path_is_missing loop0.$test_count &&
    test_path_is_symlink loop1.$test_count &&
    test_path_is_symlink newlink.$test_count
'

test_expect_success SYMLINKS 'rename($file, $symlink-circular) returns ERRNO_0' '
    touch file.$test_count &&
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    sydbox -- emily rename -e ERRNO_0 file.$test_count loop0.$test_count &&
    test_path_is_missing file.$test_count &&
    test_path_is_file loop0.$test_count &&
    test_path_is_symlink loop1.$test_count
'

test_expect_success 'rename($nofile, $newfile) returns ENOENT' '
    rm -f nofile.$test_count &&
    rm -f newfile.$test_count &&
    sydbox -- emily rename -e ENOENT nofile.$test_count newfile.$test_count &&
    test_path_is_missing nofile.$test_count &&
    test_path_is_missing newfile.$test_count
'

test_expect_success 'rename($file, $nodir/$newfile) returns ENOENT' '
    touch file.$test_count &&
    sydbox -- emily rename -e ENOENT file.$test_count nodir.$test_count/newfile &&
    test_path_is_file file.$test_count &&
    test_path_is_missing nodir.$test_count/newfile &&
    test_path_is_missing nodir.$test_count
'

test_expect_success 'rename("", $newfile) returns ENOENT' '
    sydbox -- emily rename -e ENOENT "" newfile.$test_count &&
    test_path_is_missing newfile.$test_count
'

test_expect_success 'rename($file, "") returns ENOENT' '
    touch file.$test_count &&
    sydbox -- emily rename -e ENOENT file.$test_count "" &&
    test_path_is_file file.$test_count
'

test_expect_success 'rename("", "") returns ENOENT' '
    sydbox -- emily rename -e ENOENT "" ""
'

test_expect_success 'rename($olddir, $newfile) returns ENOTDIR' '
    mkdir dir.$test_count &&
    touch file.$test_count &&
    sydbox -- emily rename -e ENOTDIR dir.$test_count file.$test_count &&
    test_path_is_dir dir.$test_count &&
    test_path_is_file file.$test_count
'

test_expect_success 'rename($olddir, $new-nonempty-dir) returns ENOTEMPTY' '
    mkdir olddir.$test_count &&
    mkdir newdir.$test_count &&
    touch newdir.$test_count/file &&
    sydbox -- emily rename -e ENOTEMPTY olddir.$test_count newdir.$test_count &&
    test_path_is_dir olddir.$test_count &&
    test_path_is_dir newdir.$test_count &&
    test_path_is_file newdir.$test_count/file
'

test_done
