#!/usr/bin/env python3

from setuptools import setup, find_packages


def get_requirements():
    with open('requirements.txt') as fd:
        return fd.read().splitlines()


setup(
    name='nvdlib',
    version='0.1',
    packages=find_packages(exclude=['tests', 'tests.*']),
    install_requires=get_requirements(),
    author='Michal Srb',
    author_email='michal@redhat.com',
    description='A small library for accessing NVD data with easy.',
    license='MIT',
    keywords='nvd mitre cve',
    url='https://github.com/msrb/nvdlib'
)
