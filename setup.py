# -*- coding: utf-8 -*-

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from zscaler_python_sdk import __version__


with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()

setup(name='zscaler_python_sdk',
      python_requires='>3.8.5',
      version=__version__,
      description='Python Interface to Zscaler API',
      long_description=long_description,
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3.8.5',
          'Natural Language :: English',
      ],
      keywords='zscaler python',
      author='omitroom13',
      author_email='NO EMAIL',
      maintainer='omitroom13',
      maintainer_email='NO EMAIL',
      url='https://github.com/omitroom13/zscaler-python-sdk/',
      license='MIT',
      packages=['zscaler_python_sdk'],
      install_requires=['requests>=2.24.0'],
      zip_safe=False
)
