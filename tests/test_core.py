import os

from petlib.ec import EcGroup

from claimchain.core import encode_claim, decode_claim
from claimchain.core import encode_capability, decode_capability, \
        get_capability_lookup_key
from claimchain.core import _compute_claim_key
from claimchain.crypto import PublicParams, LocalParams


def test_encode_claim_correctness():
    nonce = b"42"
    claim_label = b"george@george.com"
    claim_body = b"This is a test claim"
    claim_k = os.urandom(PublicParams.get_default().enc_key_size)

    with LocalParams.generate().as_default() as params:
        enc = encode_claim(nonce, claim_label, claim_body, claim_k)
        vrf_value, lookup_key, encrypted_body = enc

        claim2 = decode_claim(params.vrf.pk, nonce, claim_label,
                              vrf_value, encrypted_body, claim_k)
        assert claim2 == claim_body


def test_encode_cap_correctness():
    owner_params = LocalParams.generate()
    reader_params = LocalParams.generate()

    nonce = b"42"
    claim_label = b"marios@marios.com"
    vrf_value = b"1337"
    claim_k = os.urandom(PublicParams.get_default().enc_key_size)

    with owner_params.as_default():
        lookup_key, encrypted_capability = encode_capability(
                reader_params.dh.pk, nonce, claim_label, vrf_value, claim_k)

    with reader_params.as_default():
        lookup_key2 = get_capability_lookup_key(
                owner_params.dh.pk, nonce, claim_label)

    assert lookup_key == lookup_key2

    with reader_params.as_default():
        vrf_value2, claim_lookup_key2, claim_k2 = decode_capability(
                owner_params.dh.pk, nonce, claim_label, encrypted_capability)
    assert vrf_value == vrf_value2
    assert claim_k == claim_k2

    claim_lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    assert claim_lookup_key == claim_lookup_key2
