#!/usr/bin/env python3

"""The script decompiles the given file via RetDec R2 plugin.
The supported decompilation modes are:
   /TODO/ full      - decompile entire input file.
   selective - decompile only the function selected by the given address.
"""

import argparse
import os
import shutil
import sys

import r2pipe


class WorkingDirectory:
    def __init__(self, path):
        self.old_path = os.getcwd()
        self.path = path

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, type, value, traceback):
        os.chdir(self.old_path)


def print_error_and_die(*msg):
    print('Error:', *msg)
    sys.exit(1)


def parse_args(args):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('file',
                        metavar='FILE',
                        help='The input file.')

    parser.add_argument('-o', '--output',
                        dest='output',
                        metavar='FILE',
                        help='Output file (default: file.c). All but the last component must exist.')

    parser.add_argument('-s', '--select',
                        dest='selected_addr',
                        help='Decompile only the function selected by the given address (any address inside function). Examples: 0x1000, 4096.')

    parser.add_argument('-p', '--project',
                        dest='project_path',
                        metavar='FILE',
                        help='R2 project associated with input file.')

    parser.add_argument('-c', '--cmds',
                        dest='commands',
                        metavar='CMD1;CMD2;CMD3...',
                        help='Inital R2 commands separated by semicolon.')

    return parser.parse_args(args)


def check_args(args):
    if not args.file or not os.path.exists(args.file):
        print_error_and_die('Specified input file does not exist:', args.file)
    args.file_dir = os.path.dirname(args.file)

    if args.project_path and not os.path.exists(args.project_path):
            print_error_and_die('Specified R2 project file does not exist:', args.project_path)

    if not args.output:
        args.output = args.file + '.c'

    args.output_dir = os.path.dirname(args.output)
    if not os.path.exists(args.output_dir):
        print_error_and_die('Output directory does not exist:', args.output_dir)


def main():
    args = parse_args(sys.argv[1:])
    check_args(args)

    with WorkingDirectory(args.file_dir):
        if args.file_dir != args.output_dir:
            shutil.copy(args.file, args.output_dir)

        if args.project_path and os.path.dirname(args.project_path) != args.output_dir:
            shutil.copy(args.project_path, args.output_dir)

        r2 = r2pipe.open(args.file)

        if args.project_path:
            r2.cmd('Po ' + args.project_path)

        else:
            r2.cmd('aaa')

        if args.commands:
            cmds = args.commands.split(';')
            joining = ''

            for cmd in cmds:
                if joining:
                    joining += ";"+cmd
                    if cmd[-1] == '"':
                        r2.cmd(joining)
                        joining = ''

                elif cmd[0] == '"' and cmd[-1] != '"':
                    joining = cmd

                else:
                    r2.cmd(cmd)

        if args.selected_addr:
            r2.cmd('s ' + args.selected_addr)

        out = r2.cmd('pdz')

        r2.quit()

        try:
            with open(args.output, "w") as f:
                f.write(out)

        except Exception as e:
            sys.stderr.write('Unable to open file '+str(e))

    return 0


if __name__ == "__main__":
    main()
