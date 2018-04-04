import pytest
import hippiepug as pug

from petlib.pack import encode, decode

from claimchain.state import ClaimchainBuilder, Claimchain, Payload
from claimchain.core import get_capability_lookup_key
from claimchain.core import _compute_claim_key, _salt_label
from claimchain.crypto import PublicParams, LocalParams, compute_vrf
from claimchain.utils import ascii2bytes


@pytest.fixture
def object_store():
    return pug.store.Sha256DictStore()


@pytest.fixture(scope="module", autouse=True)
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


@pytest.fixture
def builder(object_store):
    return ClaimchainBuilder(object_store)


def test_build_payload(local_params):
    mtr_hash = b'totally_a_tree_hash'
    nonce = b'very_random_nonce'
    payload = Payload.build(mtr_hash, nonce)
    assert payload.mtr_hash == mtr_hash
    assert ascii2bytes(payload.nonce) == nonce
    assert payload.metadata.params == local_params.export()


def test_parse_payload(local_params):
    payload = Payload.build(Tree(), b'nonce')
    exported = payload.export()
    payload1 = Payload.from_dict(exported)

    # Check if original dicitonary is not parsed
    assert isinstance(exported['metadata'], dict)


def test_add_claim(builder):
    builder["marios"] = "test"
    assert builder["marios"] == "test"


def test_clear(builder):
    builder["marios"] = "test"
    builder.clear()
    with pytest.raises(KeyError):
        builder["marios"]


def test_grant_access(builder):
    builder["marios"] = "test"
    builder["carmela"] = "test"

    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    builder.grant_access(reader_params.dh.pk, ["marios", "carmela"])
    assert set(builder.get_capabilities(reader_pk)) == {"marios", "carmela"}

    builder.revoke_access(reader_params.dh.pk, ["marios"])
    assert set(builder.get_capabilities(reader_pk)) == {"carmela"}


def commit_claims(builder, object_store, claims, caps=None):
    for label, content in claims:
        builder[label] = content
    for reader_dh_pk, label in (caps or []):
        builder.grant_access(reader_dh_pk, label)

    head = builder.commit(object_store)

    block = store[head]
    block_content = block.items[0]
    nonce = ascii2bytes(block_content['nonce'])

    # Get associated Merkle tree
    mtr_hash = ascii2bytes(block_content['mtr_hash'])
    tree = hippiepug.Tree(store, root_hash=mtr_hash)
    return nonce, chain, tree


def test_tree_contains_claim_lookup_key(object_store):
    builder = ClaimchainBuilder()
    nonce, chain, tree = commit_claims(
            builder, object_store, [("marios", "test")])

    salted_label = _salt_label(nonce, "marios")
    vrf = compute_vrf(salted_label)
    pp = PublicParams.get_default()

    lookup_key = _compute_claim_key(vrf.value, mode='lookup')
    root, evidence = tree.evidence(key=lookup_key)
    leaf = evidence[-1]
    assert leaf.key == lookup_key


def test_tree_contains_cap_lookup_key(object_store):
    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    builder.grant_access(reader_pk, ["marios"])

    nonce, chain, tree = commit_claims(object_store, [("marios", "test")])

    owner_pk = LocalParams.get_default().dh.pk
    with reader_params.as_default():
        lookup_key = get_capability_lookup_key(owner_pk, nonce, "marios")

    root, evidence = tree.evidence(key=lookup_key)
    leaf = evidence[-1]
    assert leaf.key == lookup_key


def test_evidence(object_store):
    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    builder.grant_access(reader_pk, ["marios"])

    nonce, chain, tree = commit_claims(object_store, [("marios", "test")])
    evidence = builder.compute_evidence_keys(reader_pk, "marios")
    assert len(evidence) > 0

    evidence_store = ObjectStore({k: tree.store[k] for k in evidence})
    verification_tree = Tree(object_store=evidence_store, root_hash=tree.root())

    with reader_params.as_default():
        view = View(source_chain=chain, source_tree=verification_tree)
        assert view["marios"] == b"test"


def test_view_missing_and_non_existent_label(builder):
    reader_params = LocalParams.generate()
    _, chain, tree = commit_claims(builder,
            [("marios", "test1"), ("bogdan", "test2")],
            [(reader_params.dh.pk, ["marios"])])

    with reader_params.as_default():
        view = View(chain)
        with pytest.raises(KeyError):
            view["george"]
        with pytest.raises(KeyError):
            view["bogdan"]


def test_view_label_retrieval(builder):
    reader_params = LocalParams.generate()
    _, chain, tree = commit_claims(builder,
            [("marios", "test1"), ("bogdan", "test2")],
            [(reader_params.dh.pk, ["marios", "bogdan"])])

    with reader_params.as_default():
        view = View(chain)
        assert view["marios"] == b"test1"
        assert view["bogdan"] == b"test2"
