# RetDec Radare2 plugin

RetDec plugin for Radare2.

## Install

```bash
$ mkdir build && cd build
$ cmake .. -DCMAKE_INSTALL_PREFIX=${RADARE_PLUGIN_PREFIX}
$ make -j $(nproc)
$ make install
```
