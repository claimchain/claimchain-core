import pytest

from claimchain.crypto.params import LocalParams
from claimchain.zk import compute_claim_proof, verify_claim_proof


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_proof_correct(local_params):
    claim_proof = compute_claim_proof(b'42', b"test@test.com", b'hi there')
    assert verify_claim_proof(local_params.vrf.pk, b'42', claim_proof, b"test@test.com", b'hi there')


# def test_vrf_incorrect_message(local_params):
#     vrf = compute_vrf(b"test@test.com")
#     assert not verify_vrf(local_params.vrf.pk, vrf, b"other@test.com")


# def test_vrf_incorrect_pubkey(local_params):
#     vrf = compute_vrf(b"test@test.com")

#     # Generate a distinct public key
#     other_params = LocalParams.generate()
#     while other_params.vrf.pk == local_params.vrf.pk:
#         other_params = LocalParams.generate()

#     assert not verify_vrf(other_params.vrf.pk, vrf,
#             b"test@test.com")


# def test_vrf_deterministic_value(local_params):
#     vrf1 = compute_vrf(b"test@test.com")
#     vrf2 = compute_vrf(b"test@test.com")
#     assert vrf1.value == vrf2.value

