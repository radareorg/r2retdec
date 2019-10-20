import json
import tempfile


class RetDecConfig:
    """
    Class representation of RetDec confiuration file.

    Object of class RetDecConfig represents wrapper around
    temporary file that is capable of writing required info
    about decompiled binary into text file that can be then
    passed to RetDec during decompilation.

    Objects of this class are ment to be constructed with `with`
    statement so that opened files would be closed properly on
    destruction.
    """
    def __init__(self):
        self._config = {}

    def __enter__(self):
        self._tmp_file = tempfile.NamedTemporaryFile()
        return self

    def __exit__(self, type, value, traceback):
        self._tmp_file.close()

    def write_functions(self, functions, offset_converter, type_converter):
        """Write functions to the output configuration file.
        """
        self._config.update({
            'functions': [
                self._prepare_function(
                        func, offset_converter, type_converter
                ) for func in functions
            ]
        })

        self._write_config()

    def write_globals(self, globs, type_converter):
        """Write global variables to the output configuration file.
        """
        self._config.update({
            'globals': [
                self._prepare_global(
                        glob, type_converter
                ) for glob in globs
            ]
        })
        self._write_config()

    def _prepare_function(self, func, oc, tc):
        """Convert function object into form recognizable by RetDec.
        """
        prepared_locals = [
            self._prepare_var(sp, oc, tc) for sp in func['locals']['sp_based']
        ]
        prepared_locals += [
            self._prepare_var(bp, oc, tc) for bp in func['locals']['bp_based']
        ]
        prepared_args = [
            self._prepare_arg(arg, tc) for arg in func['args']
        ]

        return {
            'startAddr': func['start_addr'],
            'endAddr': func['end_addr'],
            'name': func['name'],
            'locals': prepared_locals,
            'callingConvention': func['calling_convention'],
            'parameters': prepared_args,
            'returnType': {
                'llvmIr': tc.convert(func['return'])
            }
        }

    def _prepare_arg(self, arg, type_converter):
        """Convert function argument object into form recognizable by RetDec.
        """
        return {
            'name': arg['name'],
            'realName': arg['name'],
            'type': {
                'llvmIr': type_converter.convert(arg['type'])
            }
        }

    def _prepare_var(self, var, offset_converter, type_converter):
        """Convert function local var object into form recognizable by RetDec.
        """
        return {
            'name': var['name'],
            'realName': var['name'],
            'storage': {
                'type': 'stack',
                'value': offset_converter.convert(var['offset'])
            },
            'type': {
                'llvmIr': type_converter.convert(var['type'])
            }
        }

    def _prepare_global(self, glob, type_converter):
        """Convert global var object into form recognizable by RetDec.
        """
        return {
            'name': glob['name'],
            'storage': {
                'type': 'global',
                'value': glob['addr']
            }
        }

    def _write_config(self):
        """Write config json into temporary file.
        """
        self._tmp_file.seek(0)
        self._tmp_file.write(
            str.encode(
                json.dumps(self._config, indent=4)
            )
        )

    def prepare_read(self):
        """Prepare file for reading and return nime of temporary file.
        """
        self._tmp_file.seek(0)
        return self._tmp_file.name
