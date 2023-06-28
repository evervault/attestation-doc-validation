#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char* pcr_0;
    const char* pcr_1;
    const char* pcr_2;
    const char* pcr_8;
} GoPCRs;

extern bool attest_connection(const unsigned char* cert, size_t cert_len, const GoPCRs* expected_pcs);
