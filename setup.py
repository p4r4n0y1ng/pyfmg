from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pyfmg',
    version='0.6.1',
    packages=find_packages(),
    url='https://github.com/p4r4n0y1ng/pyfmg',
    license='Apache 2.0',
    author='p4r4n0y1ng',
    author_email='jhuber@fortinet.com',
    description='Represents the base components of the Fortinet FortiManager JSON-RPC interface',
    include_package_data=True,
    long_description=long_description,
    install_requires=['requests']
)
