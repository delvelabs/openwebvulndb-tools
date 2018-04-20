#!/usr/bin/env python

try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements
from setuptools import setup


version_file = "openwebvulndb/__version__.py"
version_data = {}
with open(version_file) as f:
    code = compile(f.read(), version_file, 'exec')
    exec(code, globals(), version_data)

reqs = [str(x.req) for x in parse_requirements('./requirements.txt', session=False)]


setup(name='openwebvulndb-tools',
      version=version_data['__version__'],
      description='A collection of tools to maintain vulnerability databases.',
      author='Delve Labs inc.',
      author_email='info@delvelabs.ca',
      url='https://github.com/delvelabs/openwebvulndb-tools',
      packages=['openwebvulndb.common', 'openwebvulndb.wordpress'],
      license="GPLv2",
      install_requires=reqs)
