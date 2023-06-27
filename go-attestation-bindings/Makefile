ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: build-all
build-all: build-dynamic

.PHONY: build-dynamic
build-dynamic:
	cargo build --release
	@cp ../target/release/libgo_attestation_bindings.dylib ./lib
	go build -ldflags="-r ./lib" -o ./bin main.go

.PHONY: run
run: build-dynamic
	@./bin/main

.PHONY: clean
clean:
	rm -rf bin main_static lib/*.dylib
