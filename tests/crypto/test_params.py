import json
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

    for key in exported:
        assert not key.endswith("_sk")

    local_params1 = LocalParams.from_dict(exported)

    assert local_params1.vrf.pk == local_params.vrf.pk
    assert local_params1.sig.pk == local_params.sig.pk
    assert local_params1.dh.pk == local_params.dh.pk
    assert local_params1.rescue.pk == local_params.rescue.pk
    assert local_params1.vrf.sk is None
    assert local_params1.sig.sk is None
    assert local_params1.dh.sk is None
    assert local_params1.rescue.sk is None


def test_local_params_private_export(local_params):
    G = PublicParams.get_default().ec_group
    public_exported = local_params.public_export()
    private_exported = local_params.private_export()

    assert public_exported != private_exported
    for key, val in public_exported.items():
        assert private_exported[key] == val

    # check that export contains no bytes and is json dumpable
    data = json.dumps(private_exported)
    imp = json.loads(data)

    local_params1 = LocalParams.from_dict(imp)

    assert local_params1.vrf.sk == local_params.vrf.sk
    assert local_params1.sig.sk == local_params.sig.sk
