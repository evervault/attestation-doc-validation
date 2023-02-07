# Attestation Doc Validation

This repo contains several projects relating to the Remote Attestation Protocol used by Evervault Cages.

- The [Attestation doc](./Attestation.md) discusses the protocol in depth.
- [attestation-doc-validation](./attestation-doc-validation/) contains a rust crate which implements the core logic required for attesting a Cage (validating certs, and attestation docs)
- [node-attestation-bindings](./node-attestation-bindings/) contains an npm module which creates bindings for consuming the rust crate from node clients

## Note: this is a beta release of this project

This branch uses pure rust libraries for validating the attestation document. The support for the curves used for attestation document signatures is incomplete.

** This crate can not validate Attestation Documents which use p521r1 **

## Getting Started

To get up and running with this project you'll need `rust`, `node`, `clippy`, `rustfmt`, and `cargo-make` installed.

Each project has some useful tasks defined in their `Makefile.toml`:

### Build the Project

```sh
cargo make build
```

### Run tests

```
cargo make test
```

### Format

```
cargo make format
```

### Run Clippy

```
cargo make lint
```

## Additional Notes

- This project uses pedantic clippy, so please [run clippy](#run-clippy) before committing.
- Due to the time sensitive nature of the attestation documents and their signatures, some tests require the use of libfaketime.
