# Wasm Attestation Bindings

This project contains the WASM interface for validating the PCRs presented in an Enclave attestation document in the Browser.

The attestation model in the browser differs slightly from that of backend SDKs, as the browser does not expose the Enclave's TLS
public key. This means that the attestation step only verifies the integrity and contents of the attestation document it has been given and not the
integrity of the connection. 

The wasm bindings can be tested using the static HTML client in `example.html`. To use it, the file must be served from a webserver to allow the browser
to load and register the wasm. This can be done using php (`php -S 127.0.0.1:8080`), python (`python -m http.server 8080`) or any preferred
web server.

## Usage

To validate the attestation doc for an Enclave, the attestation doc must first be loaded into the browser from the `.well-known` endpoint:

```js
const { attestation_doc: attestationDoc } = await fetch(`https://${enclaveHostname}/.well-known/attestation`).then(res => res.json());
```

The doc can then be verified using the expected PCRs:

```js
const pcrContainer = PCRs.empty();
pcrContainer.pcr0 = "my-pcr0";
const result = validateAttestationDocPcrs(attestationDoc, expectedPcrs);
if(!result) {
  throw new Error('Enclave failed to provide expected PCRs');
}
```

This will return a boolean reflecting whether or not the atestation doc represents the expected PCRs. 

## Note on High Traffic Volume Apps

As Enclaves are I/O constrained, they will struggle to serve high traffic volumes. This should be factored into the scoping of the in-Enclave
service, and the implementation of the client code calling into the Enclave to ensure that it can handle increases in latency when requesting 
the Enclave, and has a reasonable back-off policy.