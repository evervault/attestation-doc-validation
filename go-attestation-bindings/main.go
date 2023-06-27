package main

/*
#cgo LDFLAGS: -L./lib -lgo_attestation_bindings
#include <stdlib.h>
#include "./lib/go_attestation_bindings.h"
*/
import "C"

import (
	"crypto/tls"
	"fmt"
	"unsafe"
)

// Define the GoPCRs struct in Go
type GoPCRs struct {
	hashAlg string
	pcr0    string
	pcr1    string
	pcr2    string
	pcr8    string
}

func main() {
	cert := cert_cage_cert()
	certLength := uint(len(cert))

	result := callAttestConnection(cert, certLength)
	if result == 0 {
		fmt.Println("Error: Attestation 	failed")
	} else {
		fmt.Printf("Attestation succeeded with result: %d\n", result)
	}
}

func callAttestConnection(cert []byte, certLength uint) uint32 {
	cCert := C.uchar(cert)

	cCertLength := C.size_t(certLength)

	goStruct := C.GoPCRs{
		hash_alg: C.CString("SHA256"),
		pcr_0:    C.CString("PCR 0 Value"),
		pcr_1:    C.CString("PCR 1 Value"),
		pcr_2:    C.CString("PCR 2 Value"),
		pcr_8:    C.CString("PCR 8 Value"),
	}
	defer func() {
		C.free(unsafe.Pointer(goStruct.hash_alg))
		C.free(unsafe.Pointer(goStruct.pcr_0))
		C.free(unsafe.Pointer(goStruct.pcr_1))
		C.free(unsafe.Pointer(goStruct.pcr_2))
		C.free(unsafe.Pointer(goStruct.pcr_8))
	}()

	result := C.attest_connection(cCert, cCertLength, &goStruct)
	return uint32(result)
}

func cert_cage_cert() []byte {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", "hello-cage-2.app_89a080d2228e.cages.evervault.com:443", conf)
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()
	fmt.Println("Connected to", conn.RemoteAddr())
	cert := conn.ConnectionState().PeerCertificates[0]
	fmt.Println("Certificate:", cert.Subject.CommonName)
	return cert.Raw
}

// {
//   "status": "success",
//   "message": "EIF built successfully",
//   "enclaveMeasurements": {
//     "HashAlgorithm": "Sha384 { ... }",
//     "PCR0": "2f1d96a6a897cf7b9d15f2198355ac4cf13ab1b5e4f06b249e5b91bb3e1637b8d6d071f29c64ce89825a5b507c6656a9",
//     "PCR1": "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//     "PCR2": "64c193500432b8e551e82438b3636ddc0ca43413e9bcf75112e3074e9f97e62260ff5835f763bfd6b32aa55d6e3d8474",
//     "PCR8": "8da2e6c5b1d3c885a586014345cdcd4dbc078938f6f8694b84ed197a3d2ab3be1c5e78b52d18ae6a88d188fa37864497"
//   }
// }
