import attestation_doc_validation

with open('test-files/valid-attestation-doc-bytes', 'rb') as file:
    attestation_bytes = file.read()
    expected_pcrs = attestation_doc_validation.PCRs(
        pcr_0="f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b",
        pcr_1="bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
        pcr_2="d8f114da658de5481f8d9ec73907feb553560787522f705c92d7d96beed8e15e2aa611984e098c576832c292e8dc469a",
        pcr_8="8790eb3cce6c83d07e84b126dc61ca923333d6f66615c4a79157de48c5ab2418bdc60746ea7b7afbff03a1c6210201cb"
    )
    res = attestation_doc_validation.validate_attestation_doc_py(attestation_bytes, expected_pcrs)
    print(res)