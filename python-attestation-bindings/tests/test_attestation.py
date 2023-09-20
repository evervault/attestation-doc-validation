import pytest
import evervault_attestation_bindings
import base64


def test_attest_correct_pcrs():
    with open('../test-data/valid-certificate.der', 'rb') as f1, open('../test-data/valid-attestation-doc-base64', 'r') as f2:
        cert = f1.read()
        attestation_doc = base64.b64decode(f2.read().strip())
    
    pcrs = evervault_attestation_bindings.PCRs(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    result = evervault_attestation_bindings.attest_cage(cert, [pcrs], attestation_doc)

    assert result == True

def test_attest_incorrect_pcrs():
    with open('../test-data/valid-certificate.der', 'rb') as f1, open('../test-data/valid-attestation-doc-base64', 'r') as f2:
        cert = f1.read()
        attestation_doc = base64.b64decode(f2.read().strip())
    
    pcrs = evervault_attestation_bindings.PCRs(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000",
    )
    with pytest.raises(ValueError, match="The PCRs found were different to the expected values"):
        evervault_attestation_bindings.attest_cage(cert, [pcrs], attestation_doc)  
