from os import path
from codecs import open
from setuptools import setup, find_packages


INSTALL_REQUIRES = [
    'six',
    'petlib',
    'pyyaml',
    'attrs',
    'base58',
    'statistics',
    'defaultcontext>=1.1.0',
]


here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='claimchain',
    version='1.0',
    packages=['claimchain'],
    license='MIT',
    description=('Core and experimental implementation of ClaimChain, '
                 'decentralized privacy-preserving key distribution.',
    long_description=long_description,
    author='George Danezis',
    author_email='g.danezis@ucl.ac.uk',
    classifiers=[
        "Development Status :: 3 - Alpha",
	"Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
	"Natural Language :: English",
	"Operating System :: OS Independent",
	"Programming Language :: Python",
	"Programming Language :: Python :: 2",
	"Programming Language :: Python :: 2.7",
	"Programming Language :: Python :: 3",
	"Programming Language :: Python :: 3.4",
	"Programming Language :: Python :: 3.5",
	"Programming Language :: Python :: 3.6",
	"Programming Language :: Python :: Implementation :: CPython",
	"Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
    ],
    install_requires=INSTALL_REQUIRES,
)
