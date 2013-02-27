#!/usr/bin/env python
# coding: utf-8
# I am a king bee, I can buzz all night long!
# sydbox benchmarking script

from __future__ import print_function

import os, sys
import subprocess
import timeit

BEE_HIVE = (
        ("stat /dev/null 100000 times",
"""
import os
for i in range(100000):
    os.stat("/dev/null")
"""),
        ("stat /dev/sydbox/1 100000 times",
"""
import os
for i in range(100000):
    try: os.stat("/dev/sydbox/1")
    except: pass
"""),
)

def which(name):
    """ which(1) """
    for path in os.environ['PATH'].split(":"):
        rpath = os.path.join(path, name)
        if os.path.isfile(rpath) and os.access(rpath, os.X_OK):
            return rpath
    return None

def eval_ext(expr, syd=None, syd_opts=[]):
    """ Call python to evaluate an expr, optionally under sydbox """
    args = list()

    if syd is not None:
        args.append(syd)
        args.extend(syd_opts)
        args.append("--")

    args.append("python")
    args.append("-c")
    args.append(expr)

    return subprocess.call(args, stdin=sys.stdin,
                                 stdout=sys.stdout,
                                 stderr=sys.stderr,
                                 shell=False)

def run_test(name, expr):
    print(">>> Test: %s" % name)

    test_no = 1
    t = timeit.timeit('eval_ext(%r)' % expr,
                      setup='from __main__ import eval_ext',
                      number=1)
    print("\t%d: bare: %f sec" % (test_no, t))
    test_no += 1

    for choice in [(0, 0), (0, 1), (1, 0), (1, 1)]:
        opt_seize = "-mcore/trace/use_seize:%d" % choice[0]
        opt_seccomp = "-mcore/trace/use_seccomp:%d" % choice[1]
        t = timeit.timeit('eval_ext(%r, syd=%r, syd_opts=[%r, %r])' % ( expr,
                                                                        SYDBOX,
                                                                        opt_seize,
                                                                        opt_seccomp ),
                          setup='from __main__ import eval_ext',
                          number=1)
        print("\t%d: sydbox [seize:%d, seccomp:%d]: %f sec" % (test_no,
                                                               choice[0],
                                                               choice[1],
                                                               t))
        test_no += 1

def main(argv):
    global SYDBOX

    SYDBOX = "./sydbox"
    if not os.path.exists(SYDBOX):
        SYDBOX = which("sydbox")
        if SYDBOX is None:
            raise IOError("you don't seem to have built sydbox yet!")

    print("sydbox is at %s" % SYDBOX)
    for bee in BEE_HIVE:
        run_test(bee[0], bee[1])

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
