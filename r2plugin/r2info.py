import r2pipe
import re


class R2PipeError(Exception):
    """Raised when communication through r2pipe is not successful."""
    pass


class R2InfoProvider:
    """
    Simple wrapper around r2pipe that is ment to simplify data collection
    from radare2. Design of this class was chosen as is because RetDec
    and Radare2 are fast developing projects and their interfaces often
    change.
    """
    def __init__(self):
        # Create pipe with R2
        self._r2 = r2pipe.open()

    def input_file(self):
        """ Extracts input file path from r2pipe.
        """
        try:
            return self._execute('oj')[0]['uri']

        except AttributeError:
            pass

        raise R2PipeError("broken pipe")

    def fetch_current_function_address(self):
        """ Extracts address interval of currently processed function.
        """
        pdf = self._execute('pdfj')
        return (pdf['addr'], pdf['addr']+pdf['size'])

    def fetch_functions(self):
        """Fetch available functions from radare2.

        Fetches all available functions and returns them as a list of
        dictionaries in the format specified below.

        Example of returned objects:
        ```
        {
            'start_addr': 0xasdfasdf,
            'end_addr': 0xdeadbeef,
            'name': 'foo',
            'locals': [...], # See `fetch_function_locals`.
            'calling_convention': '...', # See `convert_call_conv`.
            'args': [...], # See `fetch_function_args`,
            'return': ('...', ), # See `fetch_function_return`
        }
        ```
        """
        func_list = self._execute('aflj')
        return [self._extract_function(fnc) for fnc in func_list]

    def _extract_function(self, fnc):
        """Helper function to extract one function from funciton list."""

        fname = re.sub(r'(?:fcn|sym)\.', '', fnc['name'])
        fname = re.sub(r'^[0-9][0-9a-fA-F]+', 'function_', fname)
        return {
            'start_addr': hex(fnc['offset']),
            'end_addr': hex(fnc['offset']+fnc['size']),
            'name': fname,
            'locals': self.fetch_function_locals(fnc),
            'calling_convention': self.convert_call_conv(fnc['calltype']),
            'args': self.fetch_function_args(fnc['name']),
            'return': self.fetch_function_return(fnc['name'])
        }

    def fetch_function_locals(self, func):
        """Fetch all available local varaible entries of function.

        Looks up all available local variables of function in Radare2 and
        returns them as list of objects in format specified below.

        Radare2 recognizes three types of local variables of the
        function:
          - regvars: register local variables: eg. eax, ebx, etc.
          - bpvars: local variables defined by offset from
                    base pointer: ebp (x86), rbp (x64), etc.
          - spvars: local variables defined by offset from
                    stack pointer: esp (x86), rsp (x64), etc.

        Returned structure:
        ```
        {
            'sp_based': [...],
            'bp_based': [...],
            'reg_based': [...]
        }
        ```

        Each variable object has following format:
        ```
        {
            'name': 'loki',
            'type': 'char**', # Type as a string with C type.
            'offset': -12,    # Or None in case of reg vars.
        }
        ```
        """
        bpvars = []
        if 'bpvars' in func:
            bpvars = [self._extract_local(var) for var in func['bpvars']]

        spvars = []
        if 'spvars' in func:
            spvars = [self._extract_local(var) for var in func['spvars']]

        regs = []
        if 'regvars' in func:
            regs = [self._extract_local(var, False) for var in func['regvars']]

        return {
            'sp_based': spvars,
            'bp_based': bpvars,
            'reg_based': regs
        }

    def _extract_local(self, var, offset=True):
        """Extracts local variable object.

        Args:
            var: r2 format of variable object.
            offset: if True then checks for offset otherwise expects
                    register.
        """
        ref = var['ref'] if 'ref' in var else None
        local = {
            'name': var['name'],
            'offset': None,
            'reg': None,
            'type': var['type']
        }

        if ref:
            if offset and 'offset' in ref:
                local['offset'] = ref['offset']

            elif not offset:
                local['offset'] = ref

        return local

    def fetch_function_args(self, func_name):
        """Return list of function arguments.

        Return sorted list of function arguments each having following
        structure name and type specified by C type string:

        ```
        {
            "name": "argi",
            "type": 'CTYPE'
        }
        ```

        Todo:
            * Info about storage of return type (eg. which register/stack off)

        """
        func_sign = self._execute('afcfj '+func_name)[0]
        args = func_sign['args']

        return [{
            'name': arg['name'],
            'type': arg['type']
        } for arg in args]

    def fetch_function_return(self, func_name):
        """Provide return type of function in C type string.

        Todo:
            * Info about storage of return type (eg. which register/registers)
        """
        func_sign = self._execute('afcfj '+func_name)[0]
        return func_sign['return'] if 'return' in func_sign else 'void'

    def convert_call_conv(self, call_conv):
        cc_dict = {
            # ARM
            'arm32': 'arm',
            'arm64': 'arm64',

            # MIPS
            'n32': 'mips',

            # PowerPC
            'powerpc-32': 'powerpc',
            'powerpc-64': 'powerpc64',

            # x64
            'amd64': 'unix_x64',
            'ms': 'ms_x64',

            # x86
            'borland': 'pascal_fastcall',
            'cdecl': 'cdecl',
            'cdecl-thiscall-ms': 'thiscall',
            'fastcall': 'fastcall',
            'pascal': 'pascal',
            'stdcall': 'stdcall',
            'watcom': 'watcom'
        }
        return cc_dict[call_conv] if call_conv in cc_dict else 'unknown'

    def fetch_globals(self):
        """Fetch list of global variables.

        Creates list of local variables extracted from r2pipe. Each
        global variable object has name and address provided as is shown
        below.

        Currently Radare2 does not support custom global variables so they
        are approximated from flags and global symbols that can be
        exported from Radare2.

        Structure of global variable in list:
        ```
        {
            "name": "globi",
            "addr": 0xasdfasdf
        }

        As support of global variables in Radare2 is limited, no data type
        of any global variable can be provded.
        ```
        """
        symbols = self._execute('isj')
        flags = self._execute('fj')
        funcs = self._execute('aflj')

        addr2names = {flag['offset']: flag['name'] for flag in flags}
        fncaddrs = [func['offset'] for func in funcs]

        globs = []
        for symbol in symbols:
            if self._check_symbol_is_global(symbol):
                # Omit if symbol on this address is function.
                if not symbol['vaddr'] in fncaddrs:
                    glb = {
                        'name': re.sub(r'sym\.', '', symbol['flagname']),
                        'addr': hex(symbol['vaddr'])
                    }

                    # As radare2 does not support global variables
                    # right now, we should check if user did not
                    # provided flag name on address of a found symbol.
                    if symbol['vaddr'] in addr2names:
                        glb['name'] = addr2names[symbol['vaddr']]

                    globs.append(glb)

        return globs

    def _check_symbol_is_global(self, symbol):
        """Return True if symbol may represent global variable.

        Currently Radare2 does not support global variables. If user
        wants to mark some address as global variable thay are required
        to make flag on such address.

        If this function returns True then symbol might (and might not)
        be global variable. Checking function list to see if symbol
        is not function should be done too.
        """
        return symbol['bind'] == 'GLOBAL' and symbol['type'] in ['OBJ', 'FUNC']

    def get_type_definition(self, type_name):
        """ Return definition of type specified by name.

        This method should be used only with structures and arrays
        which are types that can be named.
        """
        return self._execute('tsd {}'.format(type_name))

    def arch_wordsize(self):
        """Get wordsize of input binary architecture."""
        return self._execute('e.asm.bits')/8

    def _execute(self, r2cmd):
        """Execute specified command."""
        return self._r2.cmdj(r2cmd)
