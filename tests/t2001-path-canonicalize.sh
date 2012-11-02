#!/bin/sh
# Copyright 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='test pathname canonicalization'
. ./test-lib.sh

statinode() {
    case "$(uname -s)" in
    Linux)
        stat -c '%i' "$@"
        ;;
    Darwin)
        stat -f '%i' "$@"
        ;;
    FreeBSD)
        stat -f '%i' "$@"
        ;;
    *)
        ls -di "$@" | cut -d ' ' -f 1
        ;;
    esac
}

test_expect_success SYMLINKS setup-symlinks '
    ln -sf self self &&
    ln -sf loop0 loop1 &&
    ln -sf loop1 loop0
'

test_expect_success 'canonicalize MULTIPLE_BITS_SET -> EINVAL' '
    canontest -e EINVAL -m existing -m all_but_last -m missing /foo
'

test_expect_success 'canonicalize non-absolute path -> EINVAL' '
    canontest -e EINVAL -m existing foo
'

test_expect_success 'canonicalize empty path -> ENOENT' '
    canontest -e ENOENT -m existing ""
'

test_expect_success 'canontest -r works' '
    : > file.$test_count &&
    canontest -r file.$test_count >/dev/null
'

TRASH_DIRECTORY_R=$(canontest -r "$TRASH_DIRECTORY")
export TRASH_DIRECTORY_R

test_expect_success 'canonicalize ., .., intermediate // handling' '
    :> file.$test_count &&
    canontest -c -m existing "$TRASH_DIRECTORY_R//./..//file.$test_count"
'

test_expect_success 'canonicalize non-directory with trailing slash yields NULL' '
    :> file.$test_count &&
    canontest -e ENOTDIR -m existing "$TRASH_DIRECTORY_R/file.$test_count/"
'

test_expect_success 'canonicalize missing directory yields NULL' '
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/nodir.$test_count/.."
'

test_expect_success SYMLINKS 'canonicalize: symlinks not resolved with CAN_NOLINKS' '
    :> file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    canontest -m nolinks "$TRASH_DIRECTORY_R/link.$test_count" > out.$test_count &&
    grep -q link.$test_count out.$test_count
'

test_expect_success SYMLINKS 'canonicalize: symlinks to a file can be resolved' '
    :> file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R/link.$test_count" > out.$test_count &&
    grep -q file.$test_count out.$test_count
'

test_expect_success SYMLINKS 'canonicalize: symlinks to a directory can be resolved' '
    mkdir dir.$test_count &&
    ln -sf dir.$test_count link0.$test_count &&
    ln -sf link0.$test_count link1.$test_count &&
    ln -sf link1.$test_count link2.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R/dir.$test_count" > exp.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R/link0.$test_count" > out0.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R/link1.$test_count" > out1.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R/link2.$test_count" > out2.$test_count &&
    test_cmp exp.$test_count out0.$test_count &&
    test_cmp exp.$test_count out1.$test_count &&
    test_cmp exp.$test_count out2.$test_count
'

test_expect_success SYMLINKS 'canonicalize: symlink to a non-existing file yields NULL' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/link.$test_count"
'

test_expect_success SYMLINKS 'canonicalize: non-directory symlink with a trailing slash yields NULL' '
    : > file.$test_count &&
    ln -sf file.$test_count link.$test_count &&
    canontest -e ENOTDIR -m existing "$TRASH_DIRECTORY_R/link.$test_count/"
'

test_expect_success SYMLINKS 'canonicalize: missing directory via symlink yields NULL' '
    rm -rf nodir.$test_count &&
    ln -sf nodir.$test_count link.$test_count &&
    canontest -e ENOENT -m existing "$TRASH_DIRECTORY_R/link.$test_count/.."
'

test_expect_success SYMLINKS 'canonicalize: loop of symlinks are detected' '
    ln -sf loop0.$test_count loop1.$test_count &&
    ln -sf loop1.$test_count loop0.$test_count &&
    canontest -e ELOOP -m existing "$TRASH_DIRECTORY_R/loop1.$test_count"
'

test_expect_success 'canonicalize: alternate modes can resolve basenames' '
    rm -f nofile.$test_count &&
    canontest -m all_but_last "$TRASH_DIRECTORY_R/nofile.$test_count" > out0.$test_count &&
    grep -q nofile.$test_count out0.$test_count &&
    canontest -m missing "$TRASH_DIRECTORY_R/nofile.$test_count" > out1.$test_count &&
    grep -q nofile.$test_count out1.$test_count &&
    canontest -m all_but_last "$TRASH_DIRECTORY/nofile.$test_count/" > out2.$test_count &&
    grep -q nofile.$test_count out2.$test_count &&
    canontest -m missing "$TRASH_DIRECTORY/nofile.$test_count/" > out3.$test_count &&
    grep -q nofile.$test_count out3.$test_count
'

test_expect_success SYMLINKS 'canonicalize: alternate modes can resolve symlink basenames' '
    rm -f nofile.$test_count &&
    ln -sf nofile.$test_count link.$test_count &&
    canontest -m all_but_last "$TRASH_DIRECTORY_R/link.$test_count" > out0.$test_count &&
    grep -q nofile.$test_count out0.$test_count &&
    canontest -m missing "$TRASH_DIRECTORY_R/link.$test_count" > out1.$test_count &&
    grep -q nofile.$test_count out1.$test_count &&
    canontest -m all_but_last "$TRASH_DIRECTORY/link.$test_count/" > out2.$test_count &&
    grep -q nofile.$test_count out2.$test_count &&
    canontest -m missing "$TRASH_DIRECTORY/link.$test_count/" > out3.$test_count &&
    grep -q nofile.$test_count out3.$test_count
'

test_expect_success 'canonicalize: alternate modes can handle missing dirnames' '
    rm -fr nodir.$test_count &&
    canontest -e ENOENT -m all_but_last "$TRASH_DIRECTORY_R/nodir.$test_count/nofile" &&
    canontest -m missing "$TRASH_DIRECTORY_R/nodir.$test_count/nofile" > out.$test_count &&
    grep -q nodir.$test_count/nofile out.$test_count
'

# s -> link0
# p -> link1
# d/2 -> file0
# d/1 -> link3
test_expect_success SYMLINKS 'canonicalize: recent loop bug (before 2007-09-27)' '
    mkdir dir.$test_count &&
    ln -sf dir.$test_count link0.$test_count &&
    ln -sf link0.$test_count link1.$test_count &&
    : > dir.$test_count/file0.$test_count &&
    ln -sf ../link0.$test_count/file0.$test_count dir.$test_count/link3.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R" > expected.$test_count &&
    printf /dir.$test_count/file0.$test_count >> expected.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R"/link1.$test_count/link3.$test_count > result.$test_count &&
    test_cmp expected.$test_count result.$test_count
'

test_expect_success 'canonicalize: leading // is honoured correctly' '
    ln -sf //.//../.. link0.$test_count &&
    statinode / > inode0.$test_count &&
    statinode // > inode1.$test_count &&
    canontest -m existing -r //. > result1.$test_count &&
    canontest -m existing //. > result2.$test_count &&
    canontest -m existing -r "$TRASH_DIRECTORY_R"/link0.$test_count > result3.$test_count &&
    canontest -m existing "$TRASH_DIRECTORY_R"/link0.$test_count > result4.$test_count &&
    printf / > expected0.$test_count &&
    printf // > expected1.$test_count &&
    if test_cmp inode0.$test_count inode1.$test_count
    then
        test_cmp expected0.$test_count result1.$test_count &&
        test_cmp expected0.$test_count result2.$test_count &&
        test_cmp expected0.$test_count result3.$test_count &&
        test_cmp expected0.$test_count result4.$test_count
    else
        test_cmp expected1.$test_count result1.$test_count &&
        test_cmp expected1.$test_count result2.$test_count &&
        test_cmp expected1.$test_count result3.$test_count &&
        test_cmp expected1.$test_count result4.$test_count
    fi
'

#test_expect_success SYMLINKS 'deny stat($self-symlink) with ELOOP' '
#    sydbox -- emily stat -e ELOOP self
#'
#
#test_expect_success SYMLINKS 'deny stat($circular-symlink) with ELOOP' '
#    sydbox -- emily stat -e ELOOP loop0
#'
#
#test_expect_success SYMLINKS 'deny stat(${circular-symlink}/foo) with ELOOP' '
#    sydbox -- emily stat -e ELOOP loop0/foo
#'
#
#test_expect_success SYMLINKS 'allow lstat($circular-symlink)' '
#    sydbox -- emily stat -e ERRNO_0 -n loop0
#'
#
#test_expect_success SYMLINKS 'deny lstat(${circular-symlink}/foo) with ELOOP' '
#    sydbox -- emily stat -e ELOOP -n loop0/foo
#'

test_done
