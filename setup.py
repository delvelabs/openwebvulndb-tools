#!/usr/bin/env python
from setuptools import setup

version_file = "openwebvulndb/__version__.py"
version_data = {}
with open(version_file) as f:
    code = compile(f.read(), version_file, 'exec')
    exec(code, globals(), version_data)

setup(name='openwebvulndb-tools',
      version=version_data['__version__'],
      description='A collection of tools to maintain vulnerability databases.',
      author='Delve Labs inc.',
      python_requires='>=3.6.0,<3.9.0',
      author_email='info@delvelabs.ca',
      url='https://github.com/delvelabs/openwebvulndb-tools',
      packages=['openwebvulndb.common', 'openwebvulndb.wordpress'],
      license="GPLv2",
      install_requires=[
          "aiohttp>=3.7.3,<4.0",
          "easyinject==0.3",
          "marshmallow>=2.21.0,<3",
          "packaging==20.9",
          "lxml==4.6.2",
          "yarl==1.6.3"
      ])
