MAKE?=make
SUDO?=sudo

PREFIX=$(shell r2 -H R2_PREFIX)
R2HOME=$(shell r2 -H R2_USER_PLUGINS)
LIBEXT=$(shell r2 -H R2_LIBEXT)

all: p
	$(MAKE) -C p

asan:
	rm -rf p
	mkdir -p p
	export CFLAGS=-fsanitize=address ; \
	export CXXFLAGS=-fsanitize=address ; \
	cd p && cmake .. -DCMAKE_INSTALL_PREFIX=$(PREFIX) --config Debug

p:
	mkdir -p p && cd p && cmake .. -DCMAKE_INSTALL_PREFIX=$(PREFIX)

help: p
	make -C p help

install:
	$(SUDO) $(MAKE) -C p install
	cp -f p/src/r2plugin/core_retdec.$(LIBEXT) $(R2HOME)

uninstall:
	# TODO not implemented -$(SUDO) $(MAKE) -C p uninstall
	rm -rf /usr/local/share/retdec
	rm -rf /usr/local/include/retdec
	rm -rf /usr/local/lib/libretdec*
	rm -rf /usr/local/bin/retdec*
	rm -f $(R2HOME)/core_retdec.$(LIBEXT)

clean:

mrproper:
	rm -rf p
