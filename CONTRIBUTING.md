# Brief contribution guide

Thanks for considering to contribute to ClaimChain development! :heart:

Be sure to have looked through the ClaimChain technical report to understand what's going on. An up-to-date version can be found at [claimchain.github.io](https://claimchain.github.io). If you want to talk about technical details, please ping the authors as listed on the page. For non-technical discussion, you can use the mailing list of the [NEXTLEAP EU project](https://nextleap.eu): `nextleap (at) inria.fr`. We would be happy to hear your comments and suggestions.


## Setting up the dev environment

Run these commands:

    git clone git@github.com:claimchain/claimchain-core.git claimchain && cd claimchain
    pip install pytest
    pip install -e .

You can use `pytest` for quick testing::

    pytest

We use `tox` for testing on both versions of Python::

    tox

