from os import path
from codecs import open
from setuptools import setup, find_packages


here = path.abspath(path.dirname(__file__))


with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='claimchain',
    version='0.1.2',
    packages=['claimchain',],
    license='MIT',
    description='Core and experimental implementation of ClaimChain, decentralized PKI',
    long_description=long_description,
    author='George Danezis',
    author_email='g.danezis@ucl.ac.uk',
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
        'hippiehug >= 0.1.1',
    ],

)

