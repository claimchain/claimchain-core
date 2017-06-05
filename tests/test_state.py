import pytest

import hippiehug
from petlib.pack import encode, decode

from claimchain.state import State
from claimchain.core import get_capability_lookup_key
from claimchain.crypto import PublicParams, LocalParams, do_vrf_compute
from claimchain.utils import ascii2bytes


@pytest.fixture(scope="module", autouse=True)
def local_params():
    with LocalParams.generate().as_default() as params:
        yield params


@pytest.fixture
def state():
    return State()


def test_add_claim(state):
    state["marios"] = "test"
    assert state["marios"] == "test"


def test_clear(state):
    state["marios"] = "test"
    state.clear()
    with pytest.raises(KeyError):
        state["marios"]


def test_grant_access(state):
    state["marios"] = "test"
    state["carmela"] = "test"

    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    state.grant_access(reader_params.dh.pk, ["marios", "carmela"])
    assert set(state.get_capabilities(reader_pk)) == {"marios", "carmela"}

    state.revoke_access(reader_params.dh.pk, ["marios"])
    assert set(state.get_capabilities(reader_pk)) == {"carmela"}


def commit_claims(state, claims):
    for label, content in claims:
        state[label] = content

    store = {}
    chain = hippiehug.Chain(store)
    head = state.commit(chain)

    block = store[head]
    block_content = block.items[0]
    nonce = ascii2bytes(block_content['nonce'])

    # Get associated Merkle tree
    mtr_hash = ascii2bytes(block_content['mtr_hash'])
    tree = hippiehug.Tree(store, root_hash=mtr_hash)
    return nonce, chain, tree


def test_tree_contains_claim_lookup_key(state):
    nonce, chain, tree = commit_claims(state, [("marios", "test")])

    salted_label = encode([nonce, "marios"])
    vrf = do_vrf_compute(salted_label)
    pp = PublicParams.get_default()

    # TODO: Refactor into a separate function
    lookup_key = pp.hash_func(b"clm_lookup|" + vrf.value).digest()[:pp.short_hash_size]
    enc_key = pp.hash_func(b"clm_enc_key|" + vrf.value).digest()[:pp.enc_key_size]

    evidence = tree.evidence(key=lookup_key)
    leaf = evidence[1][-1]
    assert leaf.key == lookup_key


def test_tree_contains_cap_lookup_key(state):
    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    state.grant_access(reader_pk, ["marios"])

    nonce, chain, tree = commit_claims(state, [("marios", "test")])

    owner_pk = LocalParams.get_default().dh.pk
    with reader_params.as_default():
        lookup_key = get_capability_lookup_key(owner_pk, nonce, "marios")

    evidence = tree.evidence(key=lookup_key)
    leaf = evidence[1][-1]
    assert leaf.key == lookup_key

