from os import path
from codecs import open
from setuptools import setup, find_packages


here = path.abspath(path.dirname(__file__))


with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='claimchain',
    version='0.3.1',
    packages=["claimchain", "claimchain.crypto", "claimchain.utils"],
    license='MIT',
    description='Implementation of ClaimChain, a cryptographic data structure',
    long_description=long_description,
    author=('Bogdan Kulynych (EPFL SPRING Lab), '
            'Marios Isaakidis, George Danezis (UCL)'),
    author_email=('bogdan.kulynych@epfl.ch, '
                  'm.isaakidis@cs.ucl.ac.uk, g.danezis@ucl.ac.uk'),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security :: Cryptography'
    ],
    install_requires=[
        'six',
        'petlib',
        'pyyaml',
        'attrs',
        'base58',
        'statistics',
        'defaultcontext',
        'hippiehug >= 0.1.3',
        'profiled'
    ],

)

