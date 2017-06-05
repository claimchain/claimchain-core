import pytest

from claimchain.crypto.params import LocalParams
from claimchain.crypto.sign import sign, verify_signature


@pytest.fixture()
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_sign_correct(local_params):
    sig = sign(b"test@test.com")
    assert verify_signature(local_params.sig.pk, sig, b"test@test.com")


def test_sign_incorrect_message(local_params):
    sig = sign(b"test@test.com")
    assert not verify_signature(local_params.sig.pk, sig, b"other@test.com")


def test_sign_incorrect_pubkey(local_params):
    sig = sign(b"test@test.com")

    # Generate a distinct public key
    other_params = LocalParams.generate()
    while other_params.sig.pk == local_params.sig.pk:
        other_params = LocalParams.generate()

    assert not verify_signature(other_params.sig.pk, sig,
            b"test@test.com")


def test_sign_nondeterministic(local_params):
    sig1 = sign(b"test@test.com")
    sig2 = sign(b"test@test.com")
    assert sig1 != sig2
