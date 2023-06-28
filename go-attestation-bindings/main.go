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

func main() {
	cert := cert_cage_cert()
	// Prepare the input data
	var expectedPCRs []C.GoPCRs
	expectedPCRs = append(expectedPCRs, C.GoPCRs{
		pcr_0: C.CString("2f1d96a6a897cf7b9d15f2198355ac4cf13ab1b5e4f06b249e5b91bb3e1637b8d6d071f29c64ce89825a5b507c6656a9"),
		pcr_1: C.CString("bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
		pcr_2: C.CString("64c193500432b8e551e82438b3636ddc0ca43413e9bcf75112e3074e9f97e62260ff5835f763bfd6b32aa55d6e3d8474"),
		pcr_8: C.CString("8da2e6c5b1d3c885a586014345cdcd4dbc078938f6f8694b84ed197a3d2ab3be1c5e78b52d18ae6a88d188fa37864497"),
	})

	expectedPCRsArr := make([]C.GoPCRs, len(expectedPCRs))
	for i, pcrs := range expectedPCRs {
		expectedPCRsArr[i].pcr_0 = pcrs.pcr_0
		expectedPCRsArr[i].pcr_1 = pcrs.pcr_1
		expectedPCRsArr[i].pcr_2 = pcrs.pcr_2
		expectedPCRsArr[i].pcr_8 = pcrs.pcr_8
	}
	defer func() {
		for _, pcrs := range expectedPCRsArr {
			C.free(unsafe.Pointer(pcrs.pcr_0))
			C.free(unsafe.Pointer(pcrs.pcr_1))
			C.free(unsafe.Pointer(pcrs.pcr_2))
			C.free(unsafe.Pointer(pcrs.pcr_8))
		}
	}()

	result := C.attest_connection((*C.uchar)(&cert[0]), C.size_t(len(cert)), (*C.GoPCRs)(&expectedPCRsArr[0]), C.size_t(len(expectedPCRsArr)))

	fmt.Printf("Result: %v\n", bool(result))
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
