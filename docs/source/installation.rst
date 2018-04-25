##########
Installing
##########

For the moment, the package needs to be installed manually from Github::

    git clone git@github.com:claimchain/claimchain-core.git
    cd claimchain-core
    pip install -r requirements/base.txt
    pip install -e .

To run the tests, first install `dev` requirements::

    pip install -r requirements/dev.txt

And then run ``pytest``. To test against both Python 2 and Python 3, run
``tox``.
