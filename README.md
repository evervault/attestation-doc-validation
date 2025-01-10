# Attestation Doc Validation

This repo contains several projects relating to the Remote Attestation Protocol used by Evervault Enclaves.

- You can read more about the attestation protocol [here](https://docs.evervault.com/security/enclaves-attestation-in-tls).
- [attestation-doc-validation](./attestation-doc-validation/) contains a rust crate which implements the core logic required for attesting an Enclave (validating certs, and attestation docs)
- [node-attestation-bindings](./node-attestation-bindings/) contains an npm module which creates bindings for consuming the rust crate from node clients

**Note: This crate cannot validate Attestation Documents which use p521r1.**

## Getting Started

To get up and running with this project you'll need `rust`, `node`, `clippy`, `rustfmt`, and `cargo-make` installed.

There is more setup required to work with the python bindings. Please see the [python setup guide](#python-setup-guide) for details.

## Python Setup Guide

The python project requires [maturin](https://github.com/PyO3/maturin).

The python project requires the use of virtual environments. To get started, create a virtual env in the `python-attestation-bindings` directory:

```sh
cd python-attestation-bindings ; python -m venv ./venv
```

Activate the virtual environment:

```sh
source ./venv/bin/activate
```

You can then run a python repl in the venv. First, build the python wheel:

```sh
maturin develop
```

Then start a repl:

```sh
python
```

And import the project:

```python
import python_attestation_bindings

pcrs = python_attestation_bindings.PCRs("<pcr0>","<pcr1>","<pcr2>","<pcr8>")
python_attestation_bindings.attest_connection(<cert>, pcrs)
```

To run tests 
```sh
maturin develop && pytest
```

## Wasm Setup Guide

The WASM project requires [wasm-pack](https://rustwasm.github.io/wasm-pack/).

To build the WASM bindings, you can run the following command:

```sh
wasm-pack build ./wasm-attestation-bindings -s evervault --out-name index --release --target=web
```

This will:
- Build the wasm lib, with the output going into `./wasm-attestation-bindings/pkg`
- Sets the `scope` of the output JS package as `@evervault` (so the full name as `@evervault/wasm-attestation-bindings`)
- Use `index` as the base for each file name e.g. `index.js`, `index_bg.js`, `index_bg.wasm` etc.
- Sets the build to be a release build, targetting the web as its platform.

### Compiling WASM on Mac

It's not possible to compile the wasm bindings on Mac using the version of Clang shipped in MacOS. 
One approach to get around this is to install LLVM from homebrew, and set it as your C-Compiler using the `TARGET_CC` env var:

```sh
TARGET_CC="/opt/homebrew/opt/llvm/bin/clang" wasm-pack build ./wasm-attestation-bindings -s evervault --out-name index --release --target=web
```

### A Note on Attesting from Web Browsers

The process of attesting an Enclave involves validating the attestation document structure, its signature, the embedded PCRs, and, *crucially* that it contains the public key of the current TLS
certificate as its challenge — this final step allows us to confidently assert that the TLS connection is being terminated by the Enclave, 
and acts as a bind between the code integrity of the attestation document, and the host identity of the TLS certificate.

The attestation process is slightly hindered when performed in a web browser. Web browsers do not expose any details of the remote server's TLS certificate to the client. This makes it impossible to perform our full attestation process as we cannot check that the TLS public key is in the returned attestation document. 

This changes the trust model drastically, and should be deeply considered if integrating.

## Makefile

Each project has some useful tasks defined in their `Makefile.toml`:

### Build the Project

```sh
cargo make build
```

### Run tests

```sh
cargo make test
```

### Format

```sh
cargo make format
```

### Run Clippy

```sh
cargo make lint
```

## Additional Notes

- This project uses pedantic clippy, so please [run clippy](#run-clippy) before committing.
- Due to the time sensitive nature of the attestation documents and their signatures, some tests require the use of libfaketime.
