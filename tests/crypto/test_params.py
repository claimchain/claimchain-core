import pytest

from petlib.ec import EcPt

from claimchain.crypto.params import PublicParams, LocalParams


@pytest.fixture
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


def test_local_params_public_export(local_params):
    G = PublicParams.get_default().ec_group
    exported = local_params.public_export()

    local_params1 = LocalParams.load(exported)

    assert local_params1.vrf.pk == local_params.vrf.pk
    assert local_params1.sig.pk == local_params.sig.pk
    assert local_params1.dh.pk == local_params.dh.pk
    assert local_params1.vrf.sk is None
    assert local_params1.sig.sk is None
    assert local_params1.dh.sk is None

