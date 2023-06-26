#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

typedef struct {
    const char* hash_alg;
    const char* pcr_0;
    const char* pcr_1;
    const char* pcr_2;
    const char* pcr_8;
} GoPCRs; 

extern uint32_t
rustdemo(const unsigned char cert, size_t cert_length, GoPCRs* expected_pcrs_list);
