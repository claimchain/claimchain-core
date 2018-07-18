import pytest

from claimchain.crypto.params import LocalParams
from claimchain.crypto.vrf import compute_vrf
from claimchain.zk import compute_claim_proof, verify_claim_proof


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_proof_correct(local_params):
    proof_key = '42'
    claim_proof = compute_claim_proof('label', 'content', proof_key)
    assert verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label', 'content',
            proof_key)


def test_proof_incorrect_label(local_params):
    proof_key = '42'
    claim_proof = compute_claim_proof('label', 'content', proof_key)
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'incorrect label',
            'content', proof_key)


def test_proof_incorrect_message(local_params):
    proof_key = '42'
    claim_proof = compute_claim_proof('label', 'content', proof_key)
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label',
            'something else', proof_key)


def test_proof_incorrect_pubkey(local_params):
    proof_key = '42'
    claim_proof = compute_claim_proof('label', 'content', proof_key)
    assert not verify_claim_proof(
            local_params.vrf.pk, claim_proof, 'label',
            'something else', proof_key)

    # Generate a distinct public key
    other_params = LocalParams.generate()
    while other_params.vrf.pk == local_params.vrf.pk:
        other_params = LocalParams.generate()

    assert not verify_claim_proof(
            other_params.vrf.pk, claim_proof, 'label', 'content', proof_key)


def test_vrf_deterministic_value(local_params):
    proof_key = '42'
    claim_proof1 = compute_claim_proof('label', 'content', proof_key)
    claim_proof2 = compute_claim_proof('label', 'content', proof_key)
    assert claim_proof1.vrf_value == claim_proof2.vrf_value


def test_vrfs_are_consisten(local_params):
    proof_key = '42'
    claim_proof = compute_claim_proof('label', 'content', proof_key)
    vrf_bundle = compute_vrf('label')
    assert claim_proof.vrf_value == vrf_bundle.value
