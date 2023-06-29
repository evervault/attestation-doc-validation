#pragma once
#include <stdint.h>
#include <Foundation/NSObjCRuntime.h>

struct PCRs {
    const char* pcr_0;
    const char* pcr_1;
    const char* pcr_2;
    const char* pcr_8;
};

bool attest_connection(const uint8_t* cert, size_t cert_len, const struct PCRs* expected_pcrs_list, size_t expected_pcrs_len);
