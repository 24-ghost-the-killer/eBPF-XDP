# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
#
# Builds the XDP object. Requirements: clang/llvm >= 16, libbpf headers
# (libbpf-dev >= 1.0), bpftool (only to generate vmlinux.h).
#
#   make                 build build/xdp_main.bpf.o
#   make vmlinux         (re)generate vmlinux.h from the running kernel's BTF
#   make dump            disassemble the object with source interleaved
#   make clean

CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
LLVM_OBJDUMP?= llvm-objdump
BPFTOOL     ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
LIBBPF_INC  ?= /usr/include

BUILD := build
OBJ   := $(BUILD)/xdp_main.bpf.o
SRCS  := src/xdp_main.c
HDRS  := $(wildcard src/*.h)

# -mcpu=v3: ALU32 + JMP32 + atomics (kernel >= 5.12); our floor is 6.1.
# -g is mandatory: it produces the .BTF/.BTF.ext sections that libbpf needs
# for BTF-defined maps and CO-RE. DWARF is stripped afterwards.
#
# -fms-extensions: kernels >= 7.0 are built with it and their BTF contains
# anonymous tagged members (`struct ns_tree;` inside a struct), which
# bpftool dumps verbatim into vmlinux.h. Compiling with the same extension
# gives those types the kernel's layout; -Wno-microsoft-anon-tag keeps
# -Werror usable. Harmless for older kernels.
BPF_CFLAGS := -g -O2 -target bpf -mcpu=v3 -std=gnu11 -fms-extensions \
	-Wall -Wextra -Werror -Wno-unused-parameter -Wno-microsoft-anon-tag \
	-I src -I . -I $(LIBBPF_INC)

.PHONY: all vmlinux dump clean
all: $(OBJ)

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@

vmlinux: 
	rm -f vmlinux.h
	$(MAKE) vmlinux.h

$(BUILD):
	mkdir -p $@

$(OBJ): $(SRCS) $(HDRS) vmlinux.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $(SRCS) -o $@
	$(LLVM_STRIP) -g $@

dump: $(OBJ)
	$(CLANG) $(BPF_CFLAGS) -c $(SRCS) -o $(BUILD)/xdp_main.debug.o
	$(LLVM_OBJDUMP) -d -S --no-show-raw-insn $(BUILD)/xdp_main.debug.o

clean:
	rm -rf $(BUILD)
