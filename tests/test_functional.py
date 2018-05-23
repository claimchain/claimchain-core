from claimchain.crypto.params import LocalParams
from claimchain import State, View
from hippiehug import Chain
from claimchain.utils import pet2ascii

def test_read_claim_from_other_chain():
    for i in range(1,100):
        alice_params = LocalParams.generate()
        alice_state = State()
        alice_store = {}
        alice_chain = Chain(alice_store, None)
        alice_state.identity_info = b"Hi, I'm " + pet2ascii(alice_params.dh.pk)
        with alice_params.as_default():
            alice_head = alice_state.commit(alice_chain)
        alice_chain = Chain(alice_store, alice_head)

        bob_params = LocalParams.generate()
        bob_state = State()
        bob_store = {}
        bob_chain = Chain(bob_store, None)
        bob_state.identity_info = b"Hi, I'm " + pet2ascii(bob_params.dh.pk)
        with bob_params.as_default():
            bob_head = bob_state.commit(bob_chain)
        bob_chain = Chain(bob_store, bob_head)

        bob_pk = bob_params.dh.pk

        with alice_params.as_default():
            alice_state[b"bobs_key"] =  b"123abc"
            alice_state.grant_access(bob_pk, [b"bobs_key"])
            alice_head = alice_state.commit(alice_chain)
        alice_chain = Chain(alice_store, alice_head)

        with alice_params.as_default():
            value = View(alice_chain)[b'bobs_key'].decode('utf-8')

        assert value == "123abc"

        with bob_params.as_default():
            value = View(alice_chain)[b'bobs_key'].decode('utf-8')

        assert value == "123abc"
