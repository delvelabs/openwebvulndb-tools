#!/usr/bin/env python

from setuptools import setup

setup(name='openwebvulndb-tools',
      description='A collection of tools to maintain vulnerability databases.',
      author='Delve Labs inc.',
      author_email='info@delvelabs.ca',
      packages=['openwebvulndb.common', 'openwebvulndb.wordpress'],
      install_requires=[
          'aiohttp',
          'marshmallow',
          'easyinject',
          'packaging',
          'lxml'
      ])
