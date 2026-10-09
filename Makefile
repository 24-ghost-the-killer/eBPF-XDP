# xdp-sentinel top-level build.
#
# Native Linux (clang >= 16, libbpf-dev >= 1.0, bpftool, Rust >= 1.85):
#   make                    build BPF object + userspace (release)
#   make test               unprivileged tests: host parser tests + cargo test
#   sudo make test-bpf      verifier + BPF_PROG_TEST_RUN corpus (root)
#   sudo make test-integration  veth end-to-end test (root)
#   sudo make bench-prog    per-packet program cost microbenchmark (root)
#
# Any host with Docker (e.g. macOS): run everything in the dev container:
#   make docker-image && make docker-test

# make predefines CC=cc, so `?=` would never pick clang; use a dedicated var.
HOST_CC  ?= clang
CARGO    ?= cargo
DOCKER   ?= docker
IMAGE    ?= xdp-sentinel-dev
BUILD    := build
OBJ      := ebpf/build/xdp_main.bpf.o
BASE_OBJ := $(BUILD)/bench/baseline.bpf.o
CTL      := target/release/sentinelctl

HOST_CFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror \
	-Wno-unused-function -Wno-missing-field-initializers \
	-I ebpf/src -I tests/common
# Headers after a 14-byte Ethernet header are not 4-byte aligned; the XDP
# program performs the same unaligned loads (legal on x86-64/arm64), so the
# alignment sanitizer is disabled while ASan/UBSan stay on.
SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize=alignment -fno-omit-frame-pointer

.PHONY: all ebpf userspace test test-host test-rust test-bpf test-integration \
	verifier bench-prog lint fmt clean docker-image docker-test docker-shell

all: ebpf userspace

ebpf:
	$(MAKE) -C ebpf

userspace:
	$(CARGO) build --release --workspace

# ---------------- unprivileged tests ----------------

test: test-host test-rust

$(BUILD)/tests/test_parser: tests/parser/test_parser.c tests/common/*.h ebpf/src/*.h
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) $(SAN_FLAGS) $< -o $@

test-host: $(BUILD)/tests/test_parser
	./$(BUILD)/tests/test_parser

test-rust:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt

# ---------------- root-only tests (need a BPF-capable kernel) ----------------

$(BUILD)/tests/test_xdp: tests/bpf/test_xdp.c tests/common/*.h ebpf/src/*.h
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) -O2 $< -lbpf -o $@

test-bpf: ebpf $(BUILD)/tests/test_xdp $(BUILD)/tests/test_policy $(BUILD)/tests/test_ratelimit
	./$(BUILD)/tests/test_xdp $(OBJ)
	./$(BUILD)/tests/test_policy $(OBJ)
	./$(BUILD)/tests/test_ratelimit $(OBJ)

$(BUILD)/tests/test_policy: tests/bpf/test_policy.c tests/common/*.h ebpf/src/*.h
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) -O2 $< -lbpf -o $@

$(BUILD)/tests/test_ratelimit: tests/bpf/test_ratelimit.c tests/common/*.h ebpf/src/*.h
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) -O2 $< -lbpf -o $@

verifier: ebpf
	scripts/verifier-stats.sh $(OBJ)

test-integration: ebpf userspace
	tests/integration/veth_smoke.sh

# ---------------- benchmarks ----------------

$(BASE_OBJ): benchmarks/xdp/baseline.bpf.c ebpf/vmlinux.h
	@mkdir -p $(@D)
	$(HOST_CC) -g -O2 -target bpf -mcpu=v3 -fms-extensions -Wno-microsoft-anon-tag -I ebpf -c $< -o $@

$(BUILD)/bench/bench_prog_run: benchmarks/xdp/bench_prog_run.c tests/common/*.h ebpf/src/*.h
	@mkdir -p $(@D)
	$(HOST_CC) $(HOST_CFLAGS) -O2 $< -lbpf -o $@

ebpf/vmlinux.h:
	$(MAKE) -C ebpf vmlinux.h

bench-prog: ebpf $(BASE_OBJ) $(BUILD)/bench/bench_prog_run
	./$(BUILD)/bench/bench_prog_run $(OBJ) $(BASE_OBJ) 2000000

# ---------------- dev container ----------------

DOCKER_RUN := $(DOCKER) run --rm --privileged \
	-v "$(CURDIR)":/src \
	-v xs-cargo-registry:/usr/local/cargo/registry \
	-v xs-target:/src/target \
	$(IMAGE)

docker-image:
	$(DOCKER) build -t $(IMAGE) -f scripts/docker/Dockerfile.dev scripts/docker

# Runs the full Phase 1 suite against the container host's kernel.
docker-test:
	$(DOCKER_RUN) sh -c 'make all lint test test-bpf verifier test-integration bench-prog'

docker-shell:
	$(DOCKER) run --rm -it --privileged -v "$(CURDIR)":/src \
		-v xs-cargo-registry:/usr/local/cargo/registry -v xs-target:/src/target $(IMAGE) bash

clean:
	$(MAKE) -C ebpf clean
	rm -rf $(BUILD)
	$(CARGO) clean
