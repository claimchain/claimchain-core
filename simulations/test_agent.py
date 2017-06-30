import pytest

from hippiehug import Chain
from claimchain import View, State, LocalParams

from .agent import *


@pytest.fixture
def global_state(context):
    return GlobalState(context)


def make_agent(global_state):
    return Agent(global_state)


def test_agent_send_and_receive_email(global_state):
    alice = make_agent(global_state)
    bob = make_agent(global_state)
    carol = make_agent(global_state)

    carol_head, email_store = carol.send_message(['alice@test.com'])
    alice.receive_message('carol@test.com', carol_head, email_store)

    alice_head_1, email_store = alice.send_message(['bob@test.com'])
    assert alice_head_1 is not None

    # Alice's encryption key is public
    with PUBLIC_READER_PARAMS.as_default():
        chain = Chain(email_store, root_hash=alice_head_1)
        view = View(chain)
        key = view[ENC_KEY_LABEL]
        assert key is not None

    bob.receive_message('alice@test.com', alice_head_1, email_store)
    assert 'alice@test.com' in bob.view_buffer

    # Bob can't read the claim yet
    with pytest.raises(KeyError), bob.params.as_default():
        bob.view_buffer['alice@test.com']['carol@test.com']

    alice.add_expected_reader('bob@test.com', ['carol@test.com'])
    alice.maybe_update_chain(force=True)
    alice_head_2, email_store = alice.send_message(['bob@test.com'])

    bob.receive_message('alice@test.com', alice_head_2, email_store)
    assert bob.view_buffer['alice@test.com'].chain.head != alice_head_1

    # Even though Alice added Bob as expected reader, he still
    # can't read the claim
    with pytest.raises(KeyError), bob.params.as_default():
        bob.view_buffer['alice@test.com']['carol@test.com']

    # But as soon as Alice gets a response from Bob, she'll be able
    # to get his DH key and encode the capabilities.
    bob_head_1, email_store = bob.send_message(['alice@test.com'])
    assert bob_head_1 is not None
    alice.receive_message('bob@test.com', bob_head_1, email_store)
    alice.maybe_update_chain(force=True)
    alice_head_3, email_store = alice.send_message(['bob@test.com'])
    bob.receive_message('alice@test.com', alice_head_3, email_store)

    # Now Bob can read the claim
    with bob.params.as_default():
        assert bob.view_buffer['alice@test.com']['carol@test.com'] == carol.head

    assert len(bob.stores['alice@test.com']) > 0
    assert len(alice.sent_email_store_cache['bob@test.com']) > 0
