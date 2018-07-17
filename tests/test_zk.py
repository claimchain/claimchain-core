import pytest

from claimchain.crypto.params import LocalParams
from claimchain.zk import compute_claim_proof, verify_claim_proof


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_proof_correct(local_params):
    claim_proof = compute_claim_proof('label', 'content', '42')
    assert verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label', 'content', '42')


def test_proof_incorrect_nonce(local_params):
    claim_proof = compute_claim_proof('42', 'label', 'content')
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label', 'content', '1')


def test_proof_incorrect_label(local_params):
    claim_proof = compute_claim_proof('label', 'content', '42')
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'incorrect label', 'content', '42')


def test_proof_incorrect_message(local_params):
    claim_proof = compute_claim_proof('label', 'content', '42')
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label', 'something else', '42')


def test_proof_incorrect_pubkey(local_params):
    claim_proof = compute_claim_proof('label', 'content', '42')
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label', 'something else', '42')

    # Generate a distinct public key
    other_params = LocalParams.generate()
    while other_params.vrf.pk == local_params.vrf.pk:
        other_params = LocalParams.generate()

    assert not verify_claim_proof(
            other_params.vrf.pk, claim_proof, 'label', 'content', '42')


def test_vrf_deterministic_value(local_params):
    claim_proof1 = compute_claim_proof('label', 'content', '42')
    claim_proof2 = compute_claim_proof('label', 'content', '42')
    assert claim_proof1.vrf_value == claim_proof2.vrf_value

