# Attestation Doc Validation

This repo contains several projects relating to the Remote Attestation Protocol used by Evervault Cages.

- The [Attestation doc](./Attestation.md) discusses the protocol in depth.
- [attestation-doc-validation](./attestation-doc-validation/) contains a rust crate which implements the core logic required for attesting a Cage (validating certs, and attestation docs)
- [node-attestation-bindings](./node-attestation-bindings/) contains an npm module which creates bindings for consuming the rust crate from node clients

## Note: this is a beta release of this project

This branch uses pure rust libraries for validating the attestation document. The support for the curves used for attestation document signatures is incomplete.

**This crate can not validate Attestation Documents which use p521r1.**

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
