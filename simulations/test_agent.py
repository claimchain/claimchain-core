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
    # TODO: Bob received Carol's stuff, but disregarded back then
    #       Alice didn't send anything since.
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
    assert alice.head != alice_head0

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
    # TODO: Bob received Carol's stuff, but disregarded back then
    #       Alice didn't send anything since.
    assert bob.get_latest_view('alice').head == alice.head
    assert bob.get_latest_view('carol').head == carol.head
