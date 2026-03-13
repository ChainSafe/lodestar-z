# Lodestar-z Makefile — convenience targets for contributors
# All Zig commands can be run directly via `zig build`; this file wraps common workflows.

.PHONY: help build test test-filter test-spec test-spec-full test-spec-minimal test-spec-mainnet \
	spec-download spec-write test-int bench-deps bench bench-ssz bench-state-transition \
	bindings bindings-release js-install js-test js-lint clean

# Preset for spec tests: minimal (faster) or mainnet
PRESET ?= minimal

# Default target: show help
help:
	@echo "Lodestar-z — common targets for contributors"
	@echo ""
	@echo "  build              Build the project (zig build)"
	@echo "  test               Run all unit tests"
	@echo "  test-filter NAME   Run unit tests matching NAME (e.g. make test-filter verify)"
	@echo "  test-spec          Run all spec tests (PRESET=$(PRESET); override: make test-spec PRESET=mainnet)"
	@echo "  test-spec-minimal  Run spec tests with minimal preset (faster)"
	@echo "  test-spec-mainnet  Run spec tests with mainnet preset"
	@echo "  test-int           Run integration tests (e.g. era)"
	@echo ""
	@echo "  spec-download      Download spec test vectors (one-time or when updating spec)"
	@echo "  spec-write         Generate spec test code (after spec-download)"
	@echo "  test-spec-full     spec-download + spec-write + test-spec (fresh run)"
	@echo ""
	@echo "  bench-deps         Download ERA files (required for some benchmarks)"
	@echo "  bench              Run SSZ + hashing benchmarks"
	@echo "  bench-ssz          Run SSZ benchmarks only (attestation, block, state)"
	@echo "  bench-state-transition  Run state transition benchmarks"
	@echo ""
	@echo "  bindings           Build NAPI bindings (debug)"
	@echo "  bindings-release   Build NAPI bindings (release)"
	@echo "  js-install         Install JS deps (pnpm i)"
	@echo "  js-test            Run JS/TS tests"
	@echo "  js-lint            Lint JS/TS (pnpm biome check)"
	@echo ""
	@echo "  clean              Remove zig-out and .zig-cache"
	@echo ""

build:
	zig build

test:
	zig build test

test-filter:
ifndef NAME
	$(error Usage: make test-filter NAME=<filter>)
endif
	zig build test -- --test-filter "$(NAME)"

test-spec:
	zig build test:int -Dpreset=$(PRESET)
	zig build test:spec_tests -Dpreset=$(PRESET)
	zig build test:ssz_generic_spec_tests -Dpreset=$(PRESET)
	zig build test:ssz_static_spec_tests -Dpreset=$(PRESET)

# Download + generate + run spec tests (use when setting up or updating spec vectors)
test-spec-full: spec-write test-spec

test-spec-minimal: PRESET = minimal
test-spec-minimal: test-spec

test-spec-mainnet: PRESET = mainnet
test-spec-mainnet: test-spec

test-int:
	zig build test:int -Dpreset=$(PRESET)

spec-download:
	zig build run:download_spec_tests

spec-write: spec-download
	zig build run:write_spec_tests
	zig build run:write_ssz_generic_spec_tests
	zig build run:write_ssz_static_spec_tests

bench-deps:
	zig build run:download_era_files

bench: bench-deps
	zig build run:bench_ssz_attestation
	zig build run:bench_ssz_block
	zig build run:bench_ssz_state
	zig build run:bench_hashing
	zig build run:bench_merkle_node
	zig build run:bench_merkle_gindex

bench-ssz: bench-deps
	zig build run:bench_ssz_attestation
	zig build run:bench_ssz_block
	zig build run:bench_ssz_state

bench-state-transition: bench-deps
	zig build run:bench_process_block
	zig build run:bench_process_epoch

bindings:
	zig build build-lib:bindings

bindings-release:
	zig build build-lib:bindings -Doptimize=ReleaseSafe

js-install:
	pnpm i

js-test: js-install
	pnpm test

js-lint:
	pnpm biome check

clean:
	rm -rf zig-out .zig-cache
