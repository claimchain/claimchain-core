import pytest

from claimchain.crypto.params import LocalParams
from claimchain.crypto.vrf import compute_vrf, verify_vrf


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_vrf_correct(local_params):
    vrf = compute_vrf(b"test@test.com")
    assert verify_vrf(local_params.vrf.pk, vrf, b"test@test.com")


def test_vrf_incorrect_message(local_params):
    vrf = compute_vrf(b"test@test.com")
    assert not verify_vrf(local_params.vrf.pk, vrf, b"other@test.com")


def test_vrf_incorrect_pubkey(local_params):
    vrf = compute_vrf(b"test@test.com")

    # Generate a distinct public key
    other_params = LocalParams.generate()
    while other_params.vrf.pk == local_params.vrf.pk:
        other_params = LocalParams.generate()

    assert not verify_vrf(other_params.vrf.pk, vrf,
            b"test@test.com")


def test_vrf_deterministic_value(local_params):
    vrf1 = compute_vrf(b"test@test.com")
    vrf2 = compute_vrf(b"test@test.com")
    assert vrf1.value == vrf2.value

