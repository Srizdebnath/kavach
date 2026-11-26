# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree build of kavach.ko:
#   make -C kernel/kavach-ko [KDIR=/lib/modules/$(uname -r)/build] [LLVM=1] [RUSTC=...]
# Use the compiler family the kernel was built with (LLVM=1 only for clang-built kernels) and
# exactly the rustc that built it (`CONFIG_RUSTC_VERSION_TEXT` in the kernel config): the
# kernel's prebuilt `core`/`kernel` .rmeta files only load in that compiler.
KDIR ?= /lib/modules/$(shell uname -r)/build
SRC := $(abspath $(CURDIR)/../..)
VENDORED := $(SRC)/crates/kavach-common/src/abi.rs $(SRC)/crates/kavach-common/src/addr.rs \
	    $(SRC)/crates/kavach-core/src/lib.rs

all: modules

modules: kavach_vendor.rs
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

kavach_vendor.rs: vendor.sh $(VENDORED)
	./vendor.sh > $@.tmp
	mv $@.tmp $@

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f kavach_vendor.rs kavach_vendor.rs.tmp

.PHONY: all modules clean
