// swift-tools-version: 5.8

import PackageDescription

let package = Package(
    name: "AttestationBindings",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v15)
    ],
    products: [
       .library(
           name: "AttestationBindings",
           targets: ["AttestationBindings"]
       )
    ],
    targets: [
        .binaryTarget(
            name: "AttestationBindings",
//            path: "AttestationBindings.xcframework"
            url: "https://github.com/lammertw/attestation-doc-validation/releases/download/0.0.1/AttestationBindings.xcframework.zip",
            checksum: "33b3a85d0fd1e51856007bd347ad0ab88d083fb5b7c0c93fa4e66efce6a7d694"
        ),
    ]
)
