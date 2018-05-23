.. image:: https://claimchain.github.io/claimchain.svg
   :width: 50px
   :alt: ClaimChain

###############
claimchain-core
###############

.. image:: https://travis-ci.org/claimchain/claimchain-core.svg?branch=master
   :target: https://travis-ci.org/claimchain/claimchain-core
   :alt: Build Status

.. image:: https://readthedocs.org/projects/claimchain-core/badge/?version=latest
   :target: http://claimchain-core.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://zenodo.org/badge/92275408.svg
   :target: https://zenodo.org/badge/latestdoi/92275408
   :alt: Zenodo Citation

Installing
==========

You can install ``claimchain`` via pip::

    pip install claimchain

To run tests, checkout the git repository and run tox::


    git clone https://github.com/claimchain/claimchain-core
    cd claimchain-core
    tox

Usage warning
=============

This code is made for research purposes. It is not to be used in real-world systems.
Not all security features are implemented, and some of the cryptographic instantiations
need to be changed to more secure alternatives.

Usage
=====

High-level interface for ClaimChain consists of two classes, ``State`` for building claimchains, and ``View`` for parsing and interpreting claimchains.

Building chains
---------------

The core abstraction for the a ClaimChain user is a `state`. The `state` contains information about the user, and claims they make about other users or objects. Currently, this package only supports private claims, which means the owner of a chain needs to explicitly make every claim readable by intended readers. Once the `state` is constructed it can be committed to the chain.

Here is how user `Alice` would prepare her `state`::

    from claimchain import State

    state = State()

    # Alice adds information about herself
    state.identity_info = "Hi, I'm Alice"

    # Alice adds private claims
    state['bob'] = 'Bob is a good lad'

Making claims accessible requires knowing the DH public key of each authorized reader. The way to obtain the DH keys of other users is described later. Assuming Alice has Carol's DH public key, ``carol_dh_pk``, she can allow Carol to access her claim about Bob::

    state.grant_access(carol_dh_pk, ['bob'])

Note that the second argument must be an iterable of claim labels, not a single label.

To commit the state, first, a chain needs to be built, and second, the cryptographic keys have to be generated::

    from hippiehug import Chain
    from claimchain import LocalParams, State

    state = State()

    # Generate cryptographic keys
    params = LocalParams.generate()

    store = {}
    chain = Chain(store)

    with params.as_default():
        head = state.commit(chain)

The chain can then be published or transmitted to other users by publishing the ``store`` and communicating the chain's ``head``. Other users will be able to interpret the chain using the ``View`` interface, described below.


Interpreting chains
-------------------

Having access to the store (dictionary) containing other user's chain, and a head of this user's chain, one can use the ``View`` interface.

Here is how Carol can interpret Alice's claimchain, assuming Alice's store is ``alice_store``, the head of her chain is ``alice_head``, and ``params`` is Carol's ``LocalParams`` object::

    from hippiehug import Chain
    from claimchain import View

    alice_chain = Chain(alice_store, root_hash=alice_head)

    with params.as_default():
        alice_view = View(alice_chain)

        # Try to get claim with label 'bob'
        claim = alice_view['bob']

        assert claim == b'Bob is a good lad'

Finally, this is how Carol can retrieve Alice's DH public key::

    alice_dh_pk = alice_view.params.dh.pk

This DH public key can be later used to grant Alice rights to read claims on Carol's chain.


This package
============

=======================   =======================================================
claimchain/state.py       High-level ClaimChain interface
claimchain/core.py        Core operations of encoding claims and capabilities
claimchain/crypto         Cryptographic utilities, and algorithm implementations
=======================   =======================================================


Simulations
===========

A core and experimental implementation of ClaimChain, a cryptographic data
structure. See the `web page <https://claimchain.github.io>`_ to learn about
ClaimChain.

Check out the `documentation <https://claimchain-core.readthedocs.io/en/latest>`_.

Acknowledgements
================

This work is funded by the `NEXTLEAP project <https://nextleap.eu>`_ within the European
Union’s Horizon 2020 Framework Programme for Research and Innovation
(H2020-ICT-2015, ICT-10-2015) under grant agreement 688722.

