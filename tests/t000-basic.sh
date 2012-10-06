#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='basic sanity checks'
. ./test-lib.sh

test_expect_success 'sydbox' '
    type sydbox &&
    sydbox -h &&
    sydbox --help &&
    sydbox -v &&
    sydbox --version
'

test_done
