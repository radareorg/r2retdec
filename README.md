# RetDec Radare2 plugin

![retdec-r2plugin CI](https://github.com/avast/retdec-r2plugin/workflows/retdec-r2plugin%20CI/badge.svg?branch=master)

RetDec plugin for [Radare2](https://github.com/radareorg/radare2).

The plugin integrates RetDec decompiler into Radare2 console. RetDec Radare2 plugin is shipped with a bundled RetDec version, but you can use your own version (specified below).

With the bundled version of RetDec you can decompile the following architectures:
* 32-bit: Intel x86, ARM, MIPS, PIC32, and PowerPC.
* 64-bit: x86-64, ARM64 (AArch64).

## Installation and Use

The plugin was tested and should work on following operating systems: Linux, macOS and Windows.

### R2PM Installation

radare2 comes with its own package manager named 'r2pm', you can install the plugin with the following line:

```sh
$ r2pm -i r2retdec
```

This will, however, install only the plugin for r2 console. To use the Iaito plugin you must build this plugin manually. See the [Build and Installation](https://github.com/avast/retdec-r2plugin#build-and-installation) section.

```sh
$ r2pm -i r2retdec-iaito
```

### Dependencies

To compile retdec you need a relatively powerful machine with 2GB free disk and the following software installed:

On Ubuntu:

```sh
apt install autoconf libtool automake build-essential make git g++
```

For building the iaito plugin you need `qt5-default`.

### Troubleshooting

If you are not able to compile the plugin please fill an issue in github after carefully
reading the error messages in the console.

If the plugin is compiled and installed, but `pdz` doesn't show up, set the `R2_DEBUG=1`
env var to debug the plugin loading process in `radare2`.

### Use in Radare2 Console

In r2 console you can type `pdz?` to print help:

```bash
Usage: pdz   # Native RetDec decompiler plugin.
| pdz      # Show decompilation result of current function.
| pdz*     # Show current decompiled function side by side with offsets.
| pdza[?]  # Run RetDec analysis.
| pdze     # Show environment variables.
| pdzj     # Dump current decompiled function as JSON.
| pdzo     # Show current decompiled function side by side with offsets.
```

The following environment variables may be used to dynamically customize the plugin's behavior:

```bash
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
* Windows:
  * Open a command prompt (e.g. `cmd.exe`)
  * `cd retdec-r2plugin`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `cmake --build . --config Release -- -m`
  * `cmake --build . --config Release --target install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`. It is important to set the `<path>` to a location where Radare2 can load plugins from (for example `~/.local`).

You can pass the following additional parameters to `cmake`:
* `-DBUILD_BUNDLED_RETDEC=ON` to build bundled RetDec version with the plugin. The build of the bundled RetDec is by default turned on. RetDec will be installed to `CMAKE_INSTALL_PREFIX`. When turned OFF system is searched for RetDec installation.
* `-DR2PLUGIN_DOC=OFF` optional parameter to build Doxygen documentation.
* `-DBUILD_IAITO_PLUGIN=OFF` setting to ON will build the Iaito plugin.

*Note*: retdec-r2plugin requires [filesystem](https://en.cppreference.com/w/cpp/filesystem) library to be linked with the plugin. CMake will try to find the library in the system but on GCC 7 it might not be able to do so automatically. In that case you must specify a path where this library is located in the system to the cmake by adding:
* `-DCMAKE_LIBRARY_PATH=${PATH_TO_FILESTSTEM_DIR}`

On GCC 7 is `stdc++fs` located in:
* `-DCMAKE_LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/7/`

## License

Copyright (c) 2019 Avast Software, licensed under the MIT license. See the [LICENSE](https://github.com/avast/retdec-r2plugin/blob/master/LICENSE) file for more details.

RetDec Radare2 plugin uses third-party libraries or other resources listed, along with their licenses, in the [LICENSE-THIRD-PARTY](https://github.com/avast/retdec-r2plugin/blob/master/LICENSE-THIRD-PARTY) file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast/retdec/wiki/Contribution-Guidelines).
