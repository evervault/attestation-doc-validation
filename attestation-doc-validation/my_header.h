#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// Top level wrapper to show which step in the attesation process failed.
struct AttestError;

template<typename T = void, typename E = void>
struct Result;

/// Generic Result type for the top level functions of the library
template<typename T>
using AttestResult = Result<T, AttestError>;

extern "C" {

AttestResult validate_attestation_doc_2(uint8_t *attestation_doc_cose_sign_1_bytes);

} // extern "C"
