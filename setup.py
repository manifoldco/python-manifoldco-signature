from setuptools import setup, find_packages
from codecs import open
from os import path
import versioneer

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='manifoldco_signature',
    description='Verify signed HTTP requests from Manifold.',
    long_description=long_description,
    url='https://github.com/manifoldco/python-manifoldco-signature',
    license='BSD',

    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),

    packages=find_packages(),

    install_requires=['future', 'ed25519', 'iso8601'],
    extras_require={
        'test': ['pytest-runner', 'pytest'],
    },

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
)
