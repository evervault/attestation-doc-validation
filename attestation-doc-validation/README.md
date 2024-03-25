# Attestation Doc Validation

This library exposes the high level functions required by Evervault Clients to attest an Enclave per the defined [Attestation Protocol](../Attestation.md).

The library has been design to allow for bindings to be generated for multiple languages on top of the Rust crate, and should also expose enough logic to be composable for alternative Nitro Enclaves Attestation protocols.

The project makes use of `cargo make` to provide high level workflows, which can be found in the [Makefile.toml](./Makefile.toml).

## Structure

The project is split into 2 core modules:

- `attestation_doc.rs` covers all validation and parsing relating to Nitro Enclaves attestation documents.
- `cert.rs` covers all validation and parsing of X509 certs. This is to allow clients to pass off the raw pem or der encoded certs from their enclave connection to be attested.

Two high level helpers are exposed from `lib.rs`:

- `attestation_doc_validation::parse_cert` — This is a helper for parsing bytes into an X509 instance and is reasonably generic.
- `attestation_doc_validation::validate_attestation_doc_in_cert` — This drives the entire Evervault Attestation Protocol.

The underlying API is exposed through submodules. You can read more about the APIs exposed in our docs.
