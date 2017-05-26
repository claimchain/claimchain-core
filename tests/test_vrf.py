import pytest

from claimchain.crypto.params import LocalParams
from claimchain.crypto.vrf import do_vrf_compute, do_vrf_verify


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_vrf_correct(local_params):
    vrf = do_vrf_compute(b"test@test.com")
    assert do_vrf_verify(local_params.vrf.pk, vrf, b"test@test.com")


def test_vrf_incorrect_message(local_params):
    vrf = do_vrf_compute(b"test@test.com")
    assert not do_vrf_verify(local_params.vrf.pk, vrf, b"other@test.com")


def test_vrf_incorrect_pubkey(local_params):
    vrf = do_vrf_compute(b"test@test.com")

    # Generate a distinct public key
    other_params = LocalParams.generate()
    while other_params.vrf.pk == local_params.vrf.pk:
        other_params = LocalParams.generate()

    assert not do_vrf_verify(other_params.vrf.pk, vrf,
            b"test@test.com")

