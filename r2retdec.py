#!/usr/bin/env python3

from llvm_utils.ctypes import CTypeConverter

import json
import os
import re
import subprocess
import sys
import tempfile
import time

import r2pipe
r2 = r2pipe.open()


def convert_r2args(args):
    """Covnerts r2 arguments of function into RetDec config format."""
    return [{
        'name': arg['name'],
        'realName': arg['name'],
        'type': {
            'llvmIr': CTypeConverter.convert(arg['type'], r2)
        }
    } for arg in args]


def convert_offset(off):
    """Converts offset of local variable into offset used by RetDec.

    Offsets of stack variables in R2 and RetDec do not match and
    need to be converted.

    There is an error in radare2 with creating JSON that should
    hold negative numbers. These numbers are interpreted as
    unsigned 64 bit integers instead of signed. This results
    in large numbers presence in JSON instead of negative numbers.

    Current solution:
        positive signed int interval: <0, 2*63-1>
        negative signed int interval: <2**63, 2**64-1>
    """
    wordsize = int(r2.cmdj('e.asm.bits')/8)

    # the largest signed 64 bit integer
    lsigned = 2**63-1

    if isinstance(off, str) or off <= lsigned:
        return int(off) - wordsize

    # unsigned:
    #   (u)-1 == (2**64 - 1)
    #   (u)-2 == (2**64 - 2)
    #   ...
    #
    # signed:
    #   (s)(2**64 - (2**64 - 1)) == -1
    #   (s)(2**64 - (2**64 - 2)) == -2
    #   ...

    return int(off - 2**64 - wordsize)


def extract_local(var):
    """Creates variable description for RetDec config.
    """
    kind = {
        'var': 'stack',
        'arg': 'stack'
    }

    return {
        'name': var['name'],
        'realName': var['name'],
        'storage': {
            'type': kind[var['kind']],
            'value': convert_offset(var['ref']['offset'])
        },
        'type': {
            'llvmIr': CTypeConverter.convert(var['type'], r2)
        }
    }


def fetch_function_locals(bpvars, spvars):
    if bpvars is not None:
        bpvars = [extract_local(var) for var in bpvars]

    if spvars is not None:
        spvars = [extract_local(var) for var in spvars]

    return bpvars+spvars


def extract_function(fnc):
    r2params = r2.cmdj('afcfj '+fnc['name'])[0]
    fname = re.sub(r'(?:fcn|sym)\.', '', fnc['name'])
    fname = re.sub(r'^[0-9][0-9a-fA-F]+', 'function_', fname)

    bpvars = None
    if 'bpvars' in fnc:
        bpvars = fnc['bpvars']

    spvars = None
    if 'spvars' in fnc:
        spvars = fnc['spvars']

    # Another option are regvars.
    # Currently, register local variables
    # Are not fully supported by RetDec,
    # as it would require more advanced
    # register localisation.

    return {
        'startAddr': hex(fnc['offset']),
        'endAddr': hex(fnc['offset']+fnc['size']),
        'name': fname,
        'locals': fetch_function_locals(bpvars, spvars),
        'callingConvention': fnc['calltype'],
        'parameters': convert_r2args(r2params['args']),
        'returnType': {
            'llvmIr': CTypeConverter.convert(
                r2params['return'],
                r2
            ) if 'return' in r2params else 'void'
        }
    }


def fetch_functions():
    afl = r2.cmdj('aflj')

    if not afl:
        raise NotImplementedError("TODO: this error")

    return [extract_function(fnc) for fnc in afl]


def is_global(symbol):
    return symbol['bind'] == 'GLOBAL' and symbol['type'] in ['OBJ', 'FUNC']


def extract_global(symbol):
    return {
            'name': re.sub(r'sym\.', '', symbol['flagname']),
            'storage': {
                'type': 'global',
                'value': hex(symbol['vaddr'])
            }
    }


def fetch_globals(funcs):
    symbols = r2.cmdj('isj')

    if symbols is None:
        return []

    flags = r2.cmdj('fj')

    addr2names = {flag['offset']: flag['name'] for flag in flags}

    fncaddrs = None
    if funcs is not None:
        fncaddrs = [func['startAddr'] for func in funcs]

    globals = []
    for symbol in symbols:
        if is_global(symbol) and not hex(symbol['vaddr']) in fncaddrs:
            glb = extract_global(symbol)
            if symbol['vaddr'] in addr2names:
                glb['name'] = addr2names[symbol['vaddr']]

            globals.append(glb)

    return globals


def parse_args(args):
    # TODO
    pass


def check_config():
    """Checks whether ~/.r2retdec file exists and parses its content"""
    config = os.path.join(os.path.expanduser('~'), '.r2retdec')
    # TODO: should be parameter or config file
    if os.path.isfile(config):
        with open(config, 'r', encoding='ascii') as f:
            rd_path = f.read()
            if os.path.isfile(rd_path.strip()):
                return rd_path.strip()

            raise NotImplementedError(
                    "Provide exception for: not a file: {}".format(rd_path))

    raise NotImplementedError("Provide exception for this: {}".format(config))


if __name__ == "__main__":
    parse_args(sys.argv[1:])
    rd_path = check_config()
    input_file = r2.cmdj('oj')[0]['uri']
    pdf = r2.cmdj('pdfj')
    r2functions = fetch_functions()
    r2globals = fetch_globals(r2functions)
    rd_config = {
        'functions': r2functions,
        'globals': r2globals
    }

    output_file = tempfile.NamedTemporaryFile()
    tmp_json = tempfile.NamedTemporaryFile()

    tmp_json.write(str.encode(json.dumps(rd_config, indent=4)))

    tmp_json.seek(0)

    try:
        command = [
            rd_path,
            '--cleanup',
            '-o', output_file.name,
            '--select-ranges', '{}-{}'.format(
                hex(pdf.get('addr')),
                hex(pdf.get('addr') + pdf.get('size'))),
            input_file,
            '--config',
            tmp_json.name
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
        output_file.close()

    except Exception as e:
        raise NotImplementedError("Pls, handle me: {}".format(str(e)))
