#!/usr/bin/env python
# coding: utf-8

from __future__ import with_statement

import os, sys, signal
import argparse, bz2, json, re, tempfile

SIGNAME = dict((k, v) for v, k in signal.__dict__.iteritems() if v.startswith('SIG'))
sydbox_pid = -1

def sydbox(argv0, argv, fifo):
    os.environ['SHOEBOX'] = fifo

    argv.insert(0, argv0)
    os.execvp(argv0, argv)
    os._exit(127)

def handle_death(signum, frame):
    pid, status = os.waitpid(sydbox_pid, os.WUNTRACED)

    exit_code = 0
    if os.WIFEXITED(status):
        exit_code = os.WEXITSTATUS(status)
        sys.stderr.write('sydbox exited with code %d\n' % exit_code)
    if os.WIFSIGNALED(status):
        term_sig = os.WTERMSIG(status)
        sys.stderr.write('sydbox was terminated by signal %d %s\n' % (term_sig, SIGNAME[term_sig]))
        exit_code = 128 + term_sig

    sys.exit(exit_code)

def command_sydbox(args, rest):
    tmpdir = tempfile.mkdtemp()
    fifo   = os.path.join(tmpdir, 'shoebox.fifo')
    os.mkfifo(fifo, 0600)

    pid = os.fork()
    if pid == 0:
        sydbox(args.path, rest, fifo)
    else:
        global sydbox_pid
        sydbox_pid = pid

        global dump_in
        dump_in = file(fifo, 'r')

        global dump_out
        dump_out = bz2.BZ2File(args.dump, 'w')

        signal.signal(signal.SIGCHLD, handle_death)

        with dump_in, dump_out:
            for json_line in dump_in:
                dump_out.write(json_line)

def check_format(f):
    obj = json.loads(f.readline())
    if 'id' in obj and obj['id'] == 0 and 'shoebox' in obj and obj['shoebox'] == 1:
           return True
    raise IOError("Invalid format")

def dump_json(obj, fmt = None):
    if fmt is not None:
        sys.stdout.write(fmt.format(**obj) + "\n")
    else:
        json.dump(obj, sys.stdout, sort_keys = True,
                  indent = 4, separators = (',', ': '))
        sys.stdout.write('\n')

def match_any(patterns, string, flags = 0):
    for p in patterns:
        if p.match(string) is not None:
            return True
    return False

def command_show(args, rest):
    if args.pid is None:
        match_pid = None
    else:
        match_pid = [pid for l in args.pid for pid in l]

    if args.comm is None:
        match_comm = None
    else:
        match_comm = [re.compile(comm, re.UNICODE) for l in args.comm for comm in l]

    with bz2.BZ2File(args.dump, 'r') as f:
        check_format(f)
        for json_line in f.readlines():
            obj = json.loads(json_line)
            dump = list()
            dump.append(match_pid is None or
                        ('pid' in obj and obj['pid'] in match_pid))
            dump.append(match_comm is None or
                        ('process' in obj and 'comm' in obj['process'] and
                         match_any(match_comm, obj['process']['comm'])))
            if not all(dump):
                continue
            dump_json(obj, args.format)

def main():
    parser = argparse.ArgumentParser(prog='shoebox',
                                     description='Pink hiding in a shoe box',
                                     prefix_chars='+',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     # usage='%(prog)s [options] {command [arg...]}',
                                     epilog='''
Hey you, out there on the road,
Always doing what you're told,
Can you help me?

Send bug reports to "alip@exherbo.org"
Attaching poems encourages consideration tremendously.''')
    parser.add_argument('+dump', nargs=1, default = 'dump.shoebox', help = 'Path to the dump file')
    parser.add_argument('+path', nargs=1, default = 'sydbox', help = 'Path to sydbox')

    subparser = parser.add_subparsers(help = 'command help')

    parser_sydbox = subparser.add_parser('sydbox', add_help = False, help = 'Run command under Shoe Box')
    parser_sydbox.set_defaults(func = command_sydbox)

    parser_show = subparser.add_parser('show', help = 'Show dump')
    parser_show.add_argument('-f', '--format', nargs = '?',
                             help = 'Format string')
    parser_show.add_argument('-p', '--pid', nargs = '+',
                             metavar = 'PID', type = int, action = 'append',
                             help = 'PIDs to match')
    parser_show.add_argument('-c', '--comm', nargs = '+',
                             metavar = 'COMM', action = 'append',
                             help = 'COMM patterns to match (regex)')
    parser_show.set_defaults(func = command_show)

    args, rest = parser.parse_known_args()
    return args.func(args, rest)

if __name__ == '__main__':
    sys.exit(main())
