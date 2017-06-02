import pytest

import hippiehug
from petlib.pack import encode, decode

from claimchain.state import State
from claimchain.core import get_capability_lookup_key, encode_claim, _compute_claim_key
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
    nonce = ascii2bytes(block_content['payload']['nonce'])

    mtr_hash = ascii2bytes(block.items[0]['payload']['mtr_hash'])
    tree = hippiehug.Tree(store, root_hash=mtr_hash)
    return nonce, chain, tree


def test_tree_contains_claim_lookup_key(state):
    nonce, chain, tree = commit_claims(state, [("marios", "test")])
    vrf_value, lookup_key, enc_claim = encode_claim(nonce, "marios", "test")
    value, evidence = tree.evidence(key=lookup_key)
    leaf = evidence[-1]
    assert leaf.key == lookup_key

    # TODO: Uncomment once hippiehug doesn't put item hashes on the tree
    # enc_key = _compute_claim_key(vrf_value, mode='enc')
    # enc_body, tag = decode(leaf.item)
    # pp = PublicParams.get_default()
    # raw_body = pp.cipher.quick_gcm_dec(
    #         enc_key, b"\x00"*pp.enc_key_size, encrypted_body, tag)
    # (proof, claim_content) = decode(raw_body)
    # assert claim_content == "test"


def test_tree_contains_cap_lookup_key(state):
    reader_params = LocalParams.generate()
    reader_pk = reader_params.dh.pk
    state.grant_access(reader_pk, ["marios"])

    nonce, chain, tree = commit_claims(state, [("marios", "test")])

    owner_pk = LocalParams.get_default().dh.pk
    with reader_params.as_default():
        lookup_key = get_capability_lookup_key(owner_pk, nonce, "marios")

    value, evidence = tree.evidence(key=lookup_key)
    leaf = evidence[-1]
    assert leaf.key == lookup_key

    # TODO: Test value similarly to line 72
