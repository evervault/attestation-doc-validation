# Remote Attestation over TLS

[Evervault Cages](https://docs.evervault.com/products/cages) support attestation in TLS. This offers Evervault clients cryptographic guarantees about the Cage that they are speaking to.

At a most basic level, the client can guarantee that they are communicating with an Enclave directly (i.e. the TLS connection is being terminated within the enclave). This is done by validating that the attestation document embedded within the end entity certificate contains the certificate's public key as a challenge.

Clients can make increasingly strong claims about the connection using the PCRs they generated at build time. This gives them the guarantee that the enclave they are talking to is running the software exactly as they built it on their device. Additionally, they can guarantee that the software was signed by their private key before being deployed.

## How it works

When the Cage starts up, it attests itself to Evervault's Provisioner. This lets us guarantee that the PCRs of the Cage match the PCRs that you uploaded when you deployed it.

Once we're happy that the enclave is running the correct software, we provide it with an intermediate CA. This lets the Cage generate its own TLS certs to handle your requests. The private keys for its certs never leave the Enclave.

The Cage then creates its default cert. To do this, it generates a key pair, and a CSR containing all of the information needed for the cert. The generated public key is then used as a challenge to be embedded into an attestation doc. This binds the Cages cryptographic identity (its attestation document), to its TLS cert (essentially, its service identity). The CSR is then updated to include an attestable hostname in the Subject Alternative Names field: <hex-encoded-attestation-doc>.<cage-hostname>.

Whenever a client performs a TLS handshake with the Cage, it can now confidently attest it through both standard TLS, verifying the attestation document, and verifying the cyclic relationship of the two of them.

### What about nonces/liveness checks?

Cages also support the use of a nonce as a liveness check! By default, Clients will communicate with a Cage at `<cage-name>.<app-id>.cages.evervault.com`. However, by updating this request to `<nonce>.attest.<cage-name>.<app-id>.cages.evervault.com` the client is free to supply a nonce which will be embedded into the attestation document. Clients can then verify that the expected nonce is present during attestation.

## Diagram

[Cage Attestation Flow](./static//Attestation.png)
