import re


class R2OffsetConverter:
    def __init__(self, wordsize):
        self._wordsize = wordsize

    def convert(self, off):
        """Converts offset of local variable into offset used by RetDec.

        Offsets of stack variables in R2 and RetDec do not match and
        need to be converted.

        There is an error in Radare2 with creating JSON that should
        hold negative numbers. These numbers are interpreted as
        unsigned 64 bit integers instead of signed. This results
        in large numbers presence in JSON instead of negative numbers.

        Current solution:
            * positive signed int interval: <0, 2*63-1>
            * negative signed int interval: <2**63, 2**64-1>

            Each number in negative signed int interval is substracted from
            2**64 which results in negative 64 bit integer.
        """
        wordsize = int(self._wordsize)

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


class CTypeConverter:
    def __init__(self, type_info_provider):
        self._type_info = type_info_provider

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

    _type_keywords = ['const', 'struct', 'unsigned', 'signed']

    def convert(self, ctype_string):
        if ctype_string in CTypeConverter._primitives:
            return CTypeConverter._primitives[ctype_string]

        # struct a {unsigned char*, unsigned char**}
        #    -> [struct, unsigned, char, *, unsigned, char, **]
        type_tokens = re.sub(
                r'([\w\d])(\*+)',
                r'\1 \2',
                ctype_string
        ).split()

        converted = []

        while type_tokens:
            token = type_tokens.pop(0)
            if token in CTypeConverter._type_keywords:
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

            # TODO: this method might return definition of arrays in future.
            typedef = self._type_info.get_type_definition(token)
            if typedef is not None:
                # push end token
                type_tokens.insert(0, '}')
                str_search = re.search('{(.*)}', typedef)
                # TODO: This may return None, if error on side of R2 occours.

                str_elems, = str_search.groups()
                str_elems_tokens = re.sub(r'\s+', '', str_elems).split(';')
                str_elems_tokens.pop()

                for elem_token in reversed(str_elems_tokens):
                    # TODO: this shoud be recursive algorithm.
                    #       This is hovewer temporary solution
                    #       while retDec does not include support
                    #       for C types in config.

                    # Split in case of pointer
                    elem_tokens = re.sub(
                            r'([\w\d])(\*+)',
                            r'\1 \2',
                            elem_token
                    ).split()

                    for e in reversed(elem_tokens):
                        type_tokens.insert(0, e)

                    type_tokens.insert(0, ',')

                type_tokens.pop(0)
                type_tokens.insert(0, '{')

        return ''.join(converted)
