.. image:: https://claimchain.github.io/claimchain.svg
   :width: 50px
   :alt: ClaimChain

===============
claimchain-core
===============

.. image:: https://travis-ci.org/claimchain/claimchain-core.svg?branch=master
   :target: https://travis-ci.org/claimchain/claimchain-core
   :alt: Build Status

.. image:: https://readthedocs.org/projects/claimchain-core/badge/?version=latest
   :target: http://claimchain-core.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://zenodo.org/badge/92275408.svg
   :target: https://zenodo.org/badge/latestdoi/92275408
   :alt: Zenodo Citation

|

A core and experimental implementation of ClaimChain, cryptographic data
structure. See the `web page <https://claimchain.github.io>`_ to learn about
ClaimChain. Check out the `documentation <https://claimchain-core.readthedocs.io/en/latest>`_.

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
