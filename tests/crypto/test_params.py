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

    def restore(value):
        return EcPt.from_binary(value, group=G)

    assert restore(exported['vrf_pk']) == local_params.vrf.pk
    assert restore(exported['sig_pk']) == local_params.sig.pk
    assert restore(exported['dh_pk']) == local_params.dh.pk
