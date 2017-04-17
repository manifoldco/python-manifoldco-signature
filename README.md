# python-manifoldco-signature

Verify signed HTTP requests from Manifold

[Code of Conduct](./.github/CONDUCT.md) |
[Contribution Guidelines](./.github/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/tag/manifoldco/python-manifoldco-signature.svg?label=latest)](https://github.com/manifoldco/python-manifoldco-signature/releases)
[![Travis](https://img.shields.io/travis/manifoldco/python-manifoldco-signature/master.svg)](https://travis-ci.org/manifoldco/python-manifoldco-signature)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](./LICENSE.md)

## Install

```
pip install manifoldco-signature
```

## Usage

`manifoldco_signature` is built to be used with any HTTP handling framework.
As such, you'll need to manually pass in request data in the format the
`Verifier` expects.

In particular, header names must be lowercased and hyphen delimited.

If you're using a specific HTTP framework and would like native support for it
included in this library, file an issue and let us know!

```python
import manifoldco_signature as signature


verifier = signature.Verifier()

valid =  verifier.Verify('PUT', '/v1/resources', {}, {'host': 'yourdomain.com'}, 'request body')
if not valid:
    # return unauthorized
```
