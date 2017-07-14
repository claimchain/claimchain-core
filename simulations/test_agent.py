import pytest

from hippiehug import Chain
from claimchain import View, State, LocalParams

from .agent import *


@pytest.fixture
def global_state(context):
    return GlobalState(context)


def test_agent_send_and_receive_email():
    alice = Agent('alice')
    bob = Agent('bob')

    message_metadata = alice.send_message(['bob'])
    bob.receive_message('alice', message_metadata)

    assert alice.get_latest_view('bob') is None
    assert bob.get_latest_view('alice').head == alice.head

    message_metadata = bob.send_message(['alice'])
    alice.receive_message('bob', message_metadata)

    assert alice.get_latest_view('bob').head == bob.head
    assert bob.get_latest_view('alice').head == alice.head


def test_agent_cross_references():
    alice = Agent('alice')
    bob = Agent('bob')
    carol = Agent('carol')

    # Carol -> Alice
    # Alice learns about Carol
    message_metadata = carol.send_message(['alice'])
    alice.receive_message('carol', message_metadata)

    # Alice -> Bob, and Carol in CC
    message_metadata = alice.send_message(['bob', 'carol'])
    bob.receive_message('alice', message_metadata,
                        other_recipients=['carol'])

    # Bob has learned about Alice...
    assert bob.get_latest_view('alice').head == alice.head
    # ...but not about Carol
    assert bob.get_latest_view('carol') is None

    # Bob -> Alice
    message_metadata = bob.send_message(['alice'])
    alice.receive_message('bob', message_metadata)

    # Alice -> Bob once again
    message_metadata = alice.send_message(['bob'])
    bob.receive_message('alice', message_metadata)

    # Bob has learned about both Alice and Carol
    assert bob.get_latest_view('alice').head == alice.head
    assert bob.get_latest_view('carol').head == carol.head


def test_agent_chain_update():
    alice = Agent('alice')
    bob = Agent('bob')
    carol = Agent('carol')

    # Carol -> Alice
    # Alice learns about Carol
    message_metadata = carol.send_message(['alice'])
    alice.receive_message('carol', message_metadata)

    # Alice -> Bob, and Carol in CC
    alice_head0 = alice.head
    message_metadata = alice.send_message(['bob', 'carol'])
    # Alice updates her chain, because she learned about Carol
    assert alice.head != alice_head0

    bob.receive_message('alice', message_metadata,
                        other_recipients=['carol'])

    # Bob -> Alice
    bob_head0 = bob.head
    message_metadata = bob.send_message(['alice'])
    # TODO: Is this expected?
    assert bob.head == bob_head0

    alice.receive_message('bob', message_metadata)

    # Alice -> Bob once again
    alice_head1 = alice.head
    message_metadata = alice.send_message(['bob'])
    # Alice learned about Bob's head, so she updates
    assert alice.head != alice_head1

    bob.receive_message('alice', message_metadata)

    # Bob -> Alice once again
    bob_head1 = bob.head
    message_metadata = bob.send_message(['alice'])
    # TODO: Is this expected?
    assert bob.head == bob_head1
