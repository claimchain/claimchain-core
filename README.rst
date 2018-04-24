**********
ClaimChain
**********

.. image:: https://travis-ci.org/claimchain/claimchain-core.svg?branch=master
   :target: https://travis-ci.org/claimchain/claimchain-core

A core and experimental implementation of ClaimChain, cryptographic data
structure. See the `web page <https://claimchain.github.io>`_ to learn about
ClaimChain.

Usage warning
=============

This code is made for research purposes. It is not to be used in real-world systems.
Not all security features are implemented, and some of the cryptographic instantiations
need to be changed to more secure alternatives.


Installing
==========

For the moment, the package needs to be installed manually from Github::

    git clone git@github.com:claimchain/claimchain-core.git
    cd claimchain-core
    pip install -r requirements/base.txt
    pip install -e .

To run tests, install `dev` requirements::

    pip install -r requirements/dev.txt

And run::

    pytest

To test against both Python 2 and Python 3, run::

    tox


This package
============

=======================   =======================================================
claimchain/state.py       High-level ClaimChain interface
claimchain/core.py        Core operations of encoding claims and capabilities
claimchain/crypto         Cryptographic utilities, and algorithm implementations
=======================   =======================================================


Simulations
===========

The simulation and performance evaluation code, including notebooks and plots, now reside in `claimchain-simulations <https://github.com/claimchain/claimchain-simulations>`_ repo.

