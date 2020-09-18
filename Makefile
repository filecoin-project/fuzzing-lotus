SHELL := /bin/bash

here := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

FUZZ_SRC_DIR := $(here)/fuzz
LIBFUZZ_SRC_DIR := $(here)/fuzz/libfuzzer

FUZZ_BUILD_DIR := $(here)/fuzz_build

LOTUS_DIR := $(here)/code/lotus
LOTUS_FFI_DIR := $(here)/code/lotus/extern/filecoin-ffi

# hard-coded from ./code/lotus/extern/filecoin-ffi
# No problem linking them all, won't do anything at runtime if the lib is unneeded for that target
# TODO get via pkg-config?
LIBFUZZ_LDFLAGS := -L$(realpath $(LOTUS_FFI_DIR)) -lfilcrypto -lOpenCL -ldl -lgcc_s -lc -lm -lrt -lpthread -lutil

CLANG := clang
GO := go
# NOTE this doesn't pin exact versions, bingo might be worth trying when more stable
GO_FUZZ := $(GO) run github.com/dvyukov/go-fuzz/go-fuzz
GO_FUZZ_BUILD := $(GO) run github.com/dvyukov/go-fuzz/go-fuzz-build
GO114_FUZZ_BUILD := $(GO) run github.com/mdempsky/go114-fuzz-build

RUNCORPUS_PARAMS ?= -h

# Set these to pass CLI arguments to the fuzzers
FUZZ_BUILD_PARAMS :=
# FUZZ_PARAMS :=

export GO111MODULE := on

FUZZ_BIN ?= fuzzer.zip
LIBFUZZ_BIN ?= fuzzer
# go114-fuzz-build needs the full module path to correctly handle module dependencies
LIBFUZZ_PKG_NAME ?= github.com/sigp/lotus-review/fuzz/libfuzzer

#### User-defined helper functions

target_from_funcs = $(subst Fuzz,,$(1))
to_lower = $(shell echo '$(1)' | tr '[:upper:]' '[:lower:]')

####

fuzz_funcs := $(sort $(shell grep -E '^func\s+Fuzz\w+' --exclude-dir=libfuzzer -r $(FUZZ_SRC_DIR) -o -s -h | tr -s ' ' | cut -d ' ' -f 2))
fuzz_go_files := $(wildcard $(here)/fuzz/*.go)

fuzz_target_names := $(call target_from_funcs,$(fuzz_funcs))
fuzz_target_names_lower := $(call to_lower,$(fuzz_target_names))
fuzz_bin_names := $(addprefix $(FUZZ_BUILD_DIR)/, $(addsuffix /$(FUZZ_BIN), $(fuzz_target_names_lower)))

build_fuzz_goals := $(addprefix build-fuzz-, $(fuzz_target_names_lower))
run_fuzz_goals := $(addprefix run-fuzz-, $(fuzz_target_names_lower))

# internal, like a table, used to make items like JSON.json
_targets_w_lower := $(join $(addsuffix ., $(fuzz_target_names)), $(fuzz_target_names_lower))

# a user-defined func that takes in a lower-case target name and a mapping between target & lowercase
_target_from_lower_and_mapping = $(basename $(or $(filter %.$(strip $(1)), $(2)), $(warning "Not a valid target name.")))

# A makefile user-defined func to use with call
# (NOTE: relies on using '.' as a separator with basename) - know this is ok because the name must be a valid Go identifier
# Returns `HarnessName`, given a `harnessname` argument and an existing `FuzzHarnessName` fuzzing target
target_from_lower = $(call _target_from_lower_and_mapping,$(1),$(_targets_w_lower))


libfuzz_funcs := $(sort $(shell grep -E '^func\s+Fuzz\w+' -r $(LIBFUZZ_SRC_DIR) -o -s -h | tr -s ' ' | cut -d ' ' -f 2))
libfuzz_go_files := $(wildcard $(here)/fuzz/libfuzzer/*.go)

libfuzz_target_names := $(call target_from_funcs,$(libfuzz_funcs))
libfuzz_target_names_lower := $(call to_lower,$(libfuzz_target_names))
libfuzz_bin_names := $(addprefix $(FUZZ_BUILD_DIR)/, $(addsuffix /$(LIBFUZZ_BIN), $(libfuzz_target_names_lower)))

build_libfuzz_goals := $(addprefix build-fuzz-, $(libfuzz_target_names_lower))
run_libfuzz_goals := $(addprefix run-fuzz-, $(libfuzz_target_names_lower))

# internal, like a table, used to make items like JSON.json
_libfuzz_targets_w_lower := $(join $(addsuffix ., $(libfuzz_target_names)), $(libfuzz_target_names_lower))

# A makefile user-defined func to use with call
# (NOTE: relies on using '.' as a separator with basename) - know this is ok because the name must be a valid Go identifier
libfuzz_target_from_lower = $(call _target_from_lower_and_mapping,$(1),$(_libfuzz_targets_w_lower))



.PHONY: build-fuzz
build-fuzz: $(build_fuzz_goals) $(build_libfuzz_goals)
	@echo Built all fuzz targets

.PHONY: fuzz-test
fuzz-test:
	@echo "Running fuzz tests"
	cd '$(here)' && $(GO) test -tags gofuzz ./fuzz

.PHONY: fuzz-bench
fuzz-bench:
	@echo "Running fuzz benchmarks:"
	@echo "See https://golang.org/pkg/testing/#hdr-Benchmarks for more info."
	cd '$(here)' && $(GO) test -tags gofuzz -bench . -run 'Bench.*' ./fuzz

.PHONY: $(build_fuzz_goals)
$(build_fuzz_goals): build-fuzz-%: $(FUZZ_BUILD_DIR)/%/$(FUZZ_BIN)

$(fuzz_bin_names): $(FUZZ_BUILD_DIR)/%/$(FUZZ_BIN): $(fuzz_go_files) $(LOTUS_DIR)/lotus
	mkdir -p "$(FUZZ_BUILD_DIR)/$*"
	cd '$(here)' && CGO_ENABLED=0 $(GO_FUZZ_BUILD) -o "$@" -func "Fuzz$(call target_from_lower, $*)" $(FUZZ_BUILD_PARAMS) ./fuzz

.PHONY: $(run_fuzz_goals)
$(run_fuzz_goals): run-fuzz-%: $(FUZZ_BUILD_DIR)/%/$(FUZZ_BIN)
	$(GO_FUZZ) -bin "$<" -workdir "$(FUZZ_BUILD_DIR)/$*" -func "Fuzz$(call target_from_lower, $*)" $(FUZZ_PARAMS)


.PHONY: $(build_libfuzz_goals)
$(build_libfuzz_goals): build-fuzz-%: $(FUZZ_BUILD_DIR)/%/$(LIBFUZZ_BIN)

$(libfuzz_bin_names): $(FUZZ_BUILD_DIR)/%/$(LIBFUZZ_BIN): $(libfuzz_go_files) $(LOTUS_DIR)/lotus
	mkdir -p "$(FUZZ_BUILD_DIR)/$*/corpus"
	cd '$(here)' && $(GO114_FUZZ_BUILD) -o "$@.a" -func "Fuzz$(call libfuzz_target_from_lower, $*)" $(FUZZ_BUILD_PARAMS) $(LIBFUZZ_PKG_NAME)
	@# TODO other sanitizers?, 2 parts where we might want to pass params, though mainly care about the params below
	cd '$(here)' && $(CLANG) -o "$@" -fsanitize=fuzzer "$@.a" $(LIBFUZZ_LDFLAGS)
	rm "$@.a"

.PHONY: $(run_libfuzz_goals)
$(run_libfuzz_goals): run-fuzz-%: $(FUZZ_BUILD_DIR)/%/$(LIBFUZZ_BIN)
	mkdir -p "$(FUZZ_BUILD_DIR)/$*/crashers"
	cd "$(FUZZ_BUILD_DIR)/$*/crashers" && ../$(LIBFUZZ_BIN) $(FUZZ_PARAMS) "../corpus"

$(LOTUS_DIR)/lotus:
	@# mainly for other build deps, we don't actually need the full executable, but this is the easiest build target
	$(MAKE) -C $(LOTUS_DIR) lotus

# TODO forward test goals to test makefile?

# deprecated - need to update for this project if wanting to use it
#$(FUZZ_BUILD_DIR)/runcorpus:
#	$(GO) build -o "$@" $(GOFLAGS) "$(FUZZ_SRC_DIR)/runcorpus"


#.PHONY: runcorpus
#runcorpus:
#	$(GO) run $(GOFLAGS) "$(FUZZ_SRC_DIR)/runcorpus" $(RUNCORPUS_PARAMS)
#
#.PHONY: runcorpus-bin
#runcorpus-bin: $(FUZZ_BUILD_DIR)/runcorpus

.PHONY: update
update:
	cd $(here) && git submodule update --init --recursive --checkout

.PHONY: clean
clean:
	$(RM) -r $(FUZZ_BUILD_DIR)
	$(RM) $(wildcard $(here)/main.*.go)

.PHONY: mostlyclean
mostlyclean:
	$(RM) $(wildcard $(FUZZ_BUILD_DIR)/*/$(FUZZ_BIN))
	$(RM) $(wildcard $(FUZZ_BUILD_DIR)/*/$(LIBFUZZ_BIN))
	$(RM) $(wildcard $(FUZZ_BUILD_DIR)/*/$(LIBFUZZ_BIN).?)
	$(RM) $(wildcard $(here)/main.*.go)
	$(RM) $(wildcard $(FUZZ_BUILD_DIR)/*/main.*.go)


# TODO more help for passing parameters

.PHONY: help
help:
	@echo 'Maintenance:'
	@echo '============'
	@echo ""
	@echo ' Update repo and submodules:'
	@echo '    $$ make update'
	@echo ""
	@echo ""
	@echo 'Fuzzing:'
	@echo '========'
	@echo ""
	@echo "Available go-fuzz targets:"; echo -e $(addprefix "\n\t", $(fuzz_target_names_lower))
	@echo ""
	@echo "Libfuzzer targets:"; echo -e $(addprefix "\n\t", $(libfuzz_target_names_lower))
	@echo ""
	@echo 'Run fuzzer:'
	@echo '    $$ make run-fuzz-$${TARGET_NAME}'
	@echo 'Build fuzzer:'
	@echo '    $$ make build-fuzz-$${TARGET_NAME}'
	@echo 'Or build all fuzzers:'
	@echo '    $$ make build-fuzz'
	@echo ""
	@echo 'Run fuzzing related tests (e.g. replaying interesting inputs on the harnesses):'
	@echo '    $$ make fuzz-test'
	@echo ""
	@echo 'Run fuzzing related benchmarks (e.g. replaying potential DOS inputs on the harnesses):'
	@echo '    $$ make fuzz-bench'
	@echo ""
	@echo 'Fuzzer working directory set to `./fuzz_build/$${TARGET_NAME}`'
	@echo ""
	@echo 'To delete fuzzing binaries and artifacts:'
	@echo '    $$ make mostlyclean'
	@echo ""
	@echo 'To fully clean `./fuzz_build/` (inc corpora):'
	@echo '    $$ make clean'
	@echo ""
	@#echo "To run an individual test corpus:"
	@#echo '    `make RUNCORPUS_PARAMS='-h' runcorpus`'
	@#echo "or build and run the binary:"
	@#echo '    `make runcorpus-bin && $(FUZZ_SRC_DIR)/runcorpus -h`'
