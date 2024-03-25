# Swift Attestation Bindings

## Build

This library uses Rust to build a iOS compatible library for the uses the attestation bindings with Swift. You will need the rust toolchains installed that are required by the following script

```
aarch64-apple-ios
x86_64-apple-ios
aarch64-apple-ios-sim
```

```
./build-xcframework.sh
```

This will output an `AttestationBindings.xcframework.zip` in the parent folder target directory
