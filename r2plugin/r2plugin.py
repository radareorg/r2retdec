#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import tempfile

from . import r2info
from . import retdec_config
from . import utils


def parse_args(args):
    parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
            '-r', '--retdec',
            dest='rd_path',
            metavar='RETDEC_PATH',
            help='Path to the `retdec_decompiler.py`'
    )

    return parser.parse_args(args)


def check_args(args):
    if args.rd_path is not None and not os.path.isfile(args.rd_path):
        raise FileNotFoundError("not a file: {}".format(args.rd_path))


def find_retdec_path(config):
    """Checks whether ~/.r2retdec file exists and parses its content
    """
    if os.path.isfile(config):
        with open(config, 'r') as f:
            rd_path = f.read()
            if os.path.isfile(rd_path.strip()):
                return rd_path.strip()

            raise FileNotFoundError(
                "content of {config}: not a file: {rd_path}".format(
                    config=config, rd_path=rd_path)
            )

    raise FileNotFoundError("not a file: {}".format(config))


def main():
    try:
        args = parse_args(sys.argv[1:])
        check_args(args)
        if args.rd_path is not None:
            rd_path = args.rd_path

        else:
            config_file = os.path.join(os.path.expanduser('~'), '.r2retdec')
            rd_path = find_retdec_path(config_file)

    except FileNotFoundError as e:
        sys.stderr.write("Error: {}".format(str(e)))
        sys.exit(1)

    with retdec_config.RetDecConfig() as rd_config:
        output_file = tempfile.NamedTemporaryFile()

        try:
            dec_info = r2info.R2InfoProvider()
            input_file = dec_info.input_file()
            (start, end) = dec_info.fetch_current_function_address()

            functions = dec_info.fetch_functions()
            globs = dec_info.fetch_globals()

            r2off_to_rd = utils.R2OffsetConverter(dec_info.arch_wordsize())
            ctype_to_llvm = utils.CTypeConverter(dec_info)

            rd_config.write_globals(globs, ctype_to_llvm)
            rd_config.write_functions(functions, r2off_to_rd, ctype_to_llvm)

            command = [
                    rd_path,
                    '--cleanup',
                    '-o', output_file.name,
                    '--select-ranges', '{}-{}'.format(hex(start), hex(end)),
                    input_file,
                    '--config',
                    rd_config.prepare_read()
                ]

            sp = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                bufsize=1,
                close_fds=True
            )

            output, error = sp.communicate()
            sys.stderr.write(error.decode('utf-8'))

            print(output_file.read().decode('utf-8'))

        except r2info.R2PipeError as e:
            sys.stderr.write("Error: communication with r2: {}".format(str(e)))
            sys.exit(1)

        # TODO: perhaps not all exceptions
        except Exception as e:
            sys.stderr.write("Error: decompilation failed: {}".format(str(e)))
            sys.exit(1)

        finally:
            output_file.close()
