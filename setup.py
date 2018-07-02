from setuptools import setup, find_packages

setup(
    name='pyfmg',
    version='0.7.3',
    packages=find_packages(),
    url='https://github.com/p4r4n0y1ng/pyfmg',
    license='Apache 2.0',
    author='p4r4n0y1ng',
    author_email='jhuber@fortinet.com',
    description='Represents the base components of the Fortinet FortiManager JSON-RPC interface',
    include_package_data=True,
    install_requires=['requests']
)
