import os

from petlib.ec import EcGroup

from claimchain.core import encode_claim, decode_claim
from claimchain.core import encode_capability, decode_capability, \
        get_capability_lookup_key
from claimchain.core import _compute_claim_key
from claimchain.crypto import PublicParams, LocalParams


def test_encode_claim_correctness():
    nonce = b'42'
    claim_label = b'george@george.com'
    claim_body = b'This is a test claim'

    with LocalParams.generate().as_default() as params:
        enc = encode_claim(claim_label, claim_body, nonce)
        vrf_value, claim_key, proof_key, lookup_key, encoded_claim = enc

        claim_prime = decode_claim(params.vrf.pk, vrf_value, claim_label, claim_key,
                                   proof_key, encoded_claim, nonce)
        assert claim_prime == claim_body


def test_encode_cap_correctness():
    owner_params = LocalParams.generate()
    reader_params = LocalParams.generate()

    nonce = '42'
    claim_label = 'marios@marios.com'
    vrf_value = '1337'
    claim_key = os.urandom(PublicParams.get_default().enc_key_size)
    proof_key = os.urandom(PublicParams.get_default().enc_key_size)

    with owner_params.as_default():
        lookup_key1, encoded_cap = encode_capability(
                reader_params.dh.pk, claim_label, vrf_value, claim_key,
                proof_key, nonce)

    with reader_params.as_default():
        lookup_key2 = get_capability_lookup_key(
                owner_params.dh.pk, claim_label, nonce)

    assert lookup_key1 == lookup_key2

    with reader_params.as_default():
        decoded_data = decode_capability(
                owner_params.dh.pk, claim_label, encoded_cap, nonce)
        claim_lookup_key2, vrf_value2, claim_key2, proof_key2 = decoded_data

    assert vrf_value == vrf_value2
    assert claim_key == claim_key2
    assert proof_key == proof_key2

    claim_lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    assert claim_lookup_key == claim_lookup_key2

