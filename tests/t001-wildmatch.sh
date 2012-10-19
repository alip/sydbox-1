#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='check wildmatch'
. ./test-lib.sh

test_expect_success 'matching filenames or pathnames' '
    "${TEST_DIRECTORY}"/wildtest "${TEST_DIRECTORY}"/wildtest.txt
'

test_done
