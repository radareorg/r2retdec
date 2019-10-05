"""
TODO: some documentation
"""

import re
import sys

class CTypeConverter:
    """
    TODO: some documenation
    """
    _primitives = {
            'void': 'void',
            'char': 'i8',
            'short': 'i16',
            'int': 'i32',
            'long': 'i64',
            'size_t': 'i64',

            'int8_t': 'i8',
            'int16_t': 'i16',
            'int32_t': 'i32',
            'int64_t': 'i64',

            'uint8_t': 'i8',
            'uint16_t': 'i16',
            'uint32_t': 'i32',
            'uint64_t': 'i64',

            'float': 'float',
            'double': 'double'
    }

    _qualities = ['const', 'struct', 'unsigned', 'signed']

    def convert(ctypeString, r2):
        if ctypeString in CTypeConverter._primitives:
            return CTypeConverter._primitives[ctypeString]

        # struct a {unsigned char*, unsigned char**}
        #    -> [struct, unsigned, char, *, unsigned, char, **]
        type_tokens = re.sub(
                r'([\w\d])(\*+)',
                r'\1 \2',
                ctypeString
        ).split()

        converted = []

        while type_tokens:
            token = type_tokens.pop(0)
            if token in CTypeConverter._qualities:
                token = type_tokens.pop(0)

            if token in ['{', '}', ',']:
                converted.append(token)
                continue

            if token in CTypeConverter._primitives:
                converted.append(CTypeConverter._primitives[token])
                continue

            if re.search(r'\*+', token) is not None:
                converted.append(token)
                continue

            str_type = r2.cmd('tsd {}'.format(token))
            if str_type:
                # push end token
                type_tokens.insert(0, '}')
                str_type = re.search('{(.*)}', type_tokens)
                if str_type is None:
                    raise NotImplementedError(
                            'TODO: Error in r2: provide better exception')
                str_type, = str_type.groups()
                str_type = re.sub(r'\s+', '', str_type).split(';')
                str_type.pop()

                for i in reversed(str_type):
                    # recursion pls
                    elem_tokens = re.sub(
                            r'([\w\d])(\*+)',
                            r'\1 \2',
                            ctypeString
                    ).split()

                    for e in reversed(elem_tokens):
                        type_tokens.insert(0, e)

                    type_tokens.insert(0, ',')

                type_tokens.pop(0)
                type_tokens.insert(0, '{')

        return ''.join(converted)
