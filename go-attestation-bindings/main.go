package main

/*
#cgo LDFLAGS: -L./lib -lrustdemo
#include <stdlib.h>
#include "./lib/rustdemo.h"
*/
import "C"

import (
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
	cert := byte(42)
	certLength := uint(10)

	result := callRustDemo(cert, certLength)
	if result == 0 {
		fmt.Println("Error: Attestation failed")
	} else {
		fmt.Printf("Attestation succeeded with result: %d\n", result)
	}
}

func callRustDemo(cert byte, certLength uint) uint32 {
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
		// Free the allocated C strings
		C.free(unsafe.Pointer(goStruct.hash_alg))
		C.free(unsafe.Pointer(goStruct.pcr_0))
		C.free(unsafe.Pointer(goStruct.pcr_1))
		C.free(unsafe.Pointer(goStruct.pcr_2))
		C.free(unsafe.Pointer(goStruct.pcr_8))
	}()

	result := C.rustdemo(cCert, cCertLength, &goStruct)
	return uint32(result)
}
