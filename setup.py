#!/usr/bin/env python

from distutils.core import setup


def readfile(fname):
    with open(fname) as f:
        content = f.read()
    return content


setup(name='txmilter',
      version='0.0.1',
      author='Flavio Grossi',
      author_email='flaviogrossi@gmail.com',
      description='Twisted library for the Milter protocol',
      license=readfile('LICENSE'),
      long_description=readfile('README.md'),
      keywords=[ 'milter', 'twisted', 'mail' ],
      url='http://github.com/flaviogrossi/txmilter/',
      packages=[ 'txmilter', ],
      requires=[ 'twisted (>=12.0)', ],
      install_requires=[ 'twisted>=12.0', ],
      classifiers=(
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python',
          'Framework :: Twisted',
          'Topic :: Communications :: Email',
          'Topic :: Communications :: Email :: Filters',
          'Topic :: Software Development :: Libraries :: Python Modules',
      )
)
