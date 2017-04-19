from __future__ import unicode_literals
from builtins import bytes

import pytest
import base64
import datetime
import ed25519
import iso8601
import manifoldco_signature as signature


@pytest.yield_fixture
def fake_time():
    old_now = signature._now
    signature._now = lambda: datetime.datetime(2017, 3, 5, 23, 53, 8, 0, iso8601.UTC)
    yield
    signature._now = old_now

@pytest.mark.parametrize('req,expected', [
    (('get', '/foo/bar', None, None, None), 'get /foo/bar\n'),
    (('get', '/foo/bar', {'foo': '12', 'bar': '9'}, None, None), 'get /foo/bar?bar=9&foo=12\n'),
    (('get', '/foo/bar', {'foo': '12', 'bar': '9'},
        {'x-signed-headers': 'date', 'date': '2017-04-06T19:17:03Z'}, None
    ), 'get /foo/bar?bar=9&foo=12\ndate: 2017-04-06T19:17:03Z\nx-signed-headers: date\n'),
    (('get', '/foo/bar', {'foo': '12', 'bar': '9'},
        {'x-signed-headers': 'date', 'date': '2017-04-06T19:17:03Z'}, 'body'
    ), 'get /foo/bar?bar=9&foo=12\ndate: 2017-04-06T19:17:03Z\nx-signed-headers: date\nbody'),
])
def test_canonize_request(req, expected):
    canonical = signature.canonize_request(*req)
    assert canonical == bytes(expected, 'utf-8')


@pytest.mark.parametrize('header,should_error', [
    ('Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg', False),
    ('Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA ZzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg', True),
    ('FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg', True),
])
def test_signature(header, should_error):
    master_key = 'PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk'

    vk = ed25519.VerifyingKey(signature._decode_base64(master_key))
    if should_error:
        with pytest.raises(Exception):
            sig = signature.parse_signature(header, vk)
    else:
        sig = signature.parse_signature(header, vk)


def _request():
    method = 'PUT'
    path = '/v1/resources/2686c96868emyj61cgt2ma7vdntg4'
    query = {}
    headers = {
        'date': '2017-03-05T23:53:08Z',
        'host': '127.0.0.1:4567',
        'content-length': '143',
        'content-type': 'application/json',
        'x-signed-headers': 'host date content-type content-length',
        'x-signature': 'Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg',
    }
    body = '{"id":"2686c96868emyj61cgt2ma7vdntg4","plan":"low","product":"generators","region":"aws::us-east-1","user_id":"200e7aeg2kf2d6nud8jran3zxnz5j"}\n'

    return (method, path, query, headers, body)


def test_verify_good_request(fake_time):
    verifier = signature.Verifier('PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk')

    req = _request()
    assert verifier.verify(*req)


def test_verify_bad_request(fake_time):
    verifier = signature.Verifier('PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk')

    req = _request()
    req[3]['x-signature'] = 'bb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg'

    assert not verifier.verify(*req)


def test_verify_old_request():
    verifier = signature.Verifier('PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk')

    req = _request()
    assert not verifier.verify(*req)
