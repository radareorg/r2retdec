# RetDec Radare2 plugin

![retdec-r2plugin CI](https://github.com/avast/retdec-r2plugin/workflows/retdec-r2plugin%20CI/badge.svg?branch=master)

RetDec plugin for [Radare2](https://github.com/radareorg/radare2).

The plugin integrates RetDec decompiler into Radare2 console. RetDec Radare2 plugin is shipped with a bundled RetDec version, but you can use your own version (specified below).

With the bundled version of RetDec you can decompile the following architectures:
* 32-bit: Intel x86, ARM, MIPS, PIC32, and PowerPC.
* 64-bit: x86-64, ARM64 (AArch64).

## Installation and Use

We officially support Linux and macOS on which this plugin was tested.

### R2PM Installation

The r2pm package is available for Radare2 version 4.5.0 and newer. To install the plugin using r2pm use:

```bash
$ r2pm -i retdec-r2plugin
```

This will, however, install only the plugin for r2 console. To use the Cutter plugin you must build this plugin manually. See the [Build and Installation](https://github.com/avast/retdec-r2plugin#build-and-installation) section.

### Use in Radare2 Console

In r2 console you can type `pdz?` to print help:

```bash
Usage: pdz   # Native RetDec decompiler plugin.
| pdz            # Decompile current function with the RetDec decompiler.
| pdzj           # Dump the current decompiled function as JSON.
| pdzo           # Decompile current function side by side with offsets.
| pdz*           # Decompiled code is returned to r2 as a comment.
Environment:
| %RETDEC_PATH   # Path to the RetDec decompiler script.
| %DEC_SAVE_DIR  # Directory to save decompilation into.
```

The following environment variables may be used to dynamically customize the plugin's behavior:

```bash
$ export RETDEC_PATH=<path> # path to the `retdec-decompiler.py` script to be used for decompilation.
$ export DEC_SAVE_DIR=<path> # custom path for output of decompilation to be saved to.
```

## Build and Installation

This section describes a local build and installation of RetDec Radare2 plugin.

### Requirements

* A compiler supporting c++17
* CMake (version >= 3.6)
* Existing Radare2 installation (version >= 4.5.0)

To build the bundled version of RetDec see [RetDec requirements section](https://github.com/avast/retdec#requirements).

### Process

* Clone the repository:
  * `git clone https://github.com/avast/retdec-r2plugin`
* Linux and MacOS:
  * `cd retdec-r2plugin`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of processes to use for parallel build, typically number of cores + 1 gives fastest compilation time)
  * `make install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`. It is important to set the `<path>` to a location where Radare2 can load plugins from (for example `~/.local`).

You can pass the following additional parameters to `cmake`:
* `-DBUILD_BUNDLED_RETDEC=ON` to build bundled RetDec version with the plugin. The build of the bundled RetDec is by default turned on.
* `-DRETDEC_INSTALL_PREFIX=<path>` to specify the path where the bundled RetDec version will be installed or to specify the path of an existing RetDec installation (default is the value of `CMAKE_INSTALL_PREFIX`).
* `-DR2PLUGIN_DOC=OFF` optional parameter to build Doxygen documentation.
* `-DBUILD_CUTTER_PLUGIN=OFF` setting to ON will try to build Cutter plugin. The Cutter must be built with support for plugin loading, see [Cutter documentation](https://cutter.re/docs/plugins.html).

*Note*: retdec-r2plugin requires [filesystem](https://en.cppreference.com/w/cpp/filesystem) library to be linked with the plugin. CMake will try to find the library in the system but on GCC 7 it might not be able to do so automatically. In that case you must specify a path where this library is located in the system to the cmake by adding:
* `-DCMAKE_LIBRARY_PATH=${PATH_TO_FILESTSTEM_DIR}`

On GCC 7 is `stdc++fs` located in:
* `-DCMAKE_LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/7/`

## License

Copyright (c) 2019 Avast Software, licensed under the LGPLv3 license. See the [LICENSE](https://github.com/avast/retdec-r2plugin/blob/master/LICENSE) file for more details.

RetDec Radare2 plugin incorporates modified files from [r2gidra-dec](https://github.com/radareorg/r2ghidra-dec) project. The original sources are licensed under the LGPLv3 license. See the [COPYING](https://github.com/radareorg/r2ghidra-dec/blob/master/COPYING) file for more details.

RetDec Radare2 plugin uses third-party libraries or other resources listed, along with their licenses, in the [LICENSE-THIRD-PARTY](https://github.com/avast/retdec-r2plugin/blob/master/LICENSE-THIRD-PARTY) file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast/retdec/wiki/Contribution-Guidelines).
