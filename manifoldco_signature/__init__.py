from builtins import bytes

import base64
import datetime
import ed25519
import iso8601


__all__ = ['MANIFOLD_KEY', 'Verifier']


MANIFOLD_KEY = 'PtISNzqQmQPBxNlUw3CdxsWczXbIwyExxlkRqZ7E690'
MAX_TIME_SKEW = datetime.timedelta(minutes=5).total_seconds()


def parse_signature(header, master_key):
    """
    Parses and verifiers Manifold X-Signature header.

    :param header: The contents of the header.
    :param master_key: an ed25519 VerifyingKey of the pubkey used to endorse this header.
    :returns: The VerifyingKey and signature contained in the header.
    :raises: An exception if the header is not valid.
    """
    parts = header.split(' ')
    if len(parts) != 3:
        raise Exception('invalid header part length')

    sig = _decode_base64(parts[0])
    raw_sigkey = _decode_base64(parts[1])
    sigkey = ed25519.VerifyingKey(raw_sigkey)
    endorsement = _decode_base64(parts[2])
    master_key.verify(endorsement, raw_sigkey)

    return sigkey, sig


def canonize_request(method, path, query, headers, body):
    """
    Generate a canonical representation of the given request.

    :param method: String representation of the request method.
    :param path: String representation of the request path.
    :param query: Optional dict of query parameters.
    :param headers: Optional dict of request headers.
    :param body: Optional request body.
    :returns: The canonical request form as bytes.
    """
    canonical = method.lower() + ' ' + path

    if query != None:
        keys = list(query.keys())
        if len(keys) > 0:
            keys.sort()
            qs = []
            for k in keys:
                qs.append(k + '=' + query[k])
            canonical += '?' + '&'.join(qs)

    canonical += '\n'

    if headers != None:
        signed_headers = headers['x-signed-headers'].split(' ')
        signed_headers.append('x-signed-headers')
        for hdr in signed_headers:
            canonical += hdr.lower() + ': ' + headers[hdr].strip() + '\n'

    canonical = bytes(canonical, 'utf-8')
    if body != None:
        if not isinstance(body, bytes):
            body = bytes(body, 'utf-8')
        canonical += body

    return canonical


class Verifier:

    def __init__(self, master_key=MANIFOLD_KEY):
        self._master_key= ed25519.VerifyingKey(_decode_base64(master_key))

    def verify(self, method, path, query, headers, body):
        """
        Verify that the given request was sent from Manifold.

        :param method: The request method, as a string.
        :param path: The request path, as a string.
        :param query: A dict-like object containing any unescaped query parameters.
        :param headers: A dict-like object containing the request headers. The keys
                        should be lowercased.
        :param body: The request body, as a string or bytes.
        :returns: A boolean indicating if the request is valid.
        """
        try:
            sigkey, sig = parse_signature(headers['x-signature'], self._master_key)
            canonical = canonize_request(method, path, query, headers, body)
            sigkey.verify(sig, canonical)

            req_time = iso8601.parse_date(headers['date'])
            return abs((req_time - _now()).total_seconds()) <= MAX_TIME_SKEW
        except:
            return False


def _now():
    return datetime.datetime.now(iso8601.UTC)


def _decode_base64(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '='* (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
