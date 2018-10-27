from functools import wraps

from django.http import JsonResponse
from . import Verifier


def verify(master_key=None):
    """
    Verify that the given request was sent from Manifold:

    @verify()
    def my_view(request):
        pass

    """

    def decorator(f):
        @wraps(f)
        def wrapper(request, *args, **kwds):
            verifier = Verifier(master_key=master_key)

            headers = {}
            querydict = None
            for key, value in request.META.items():
                if key == "CONTENT_TYPE":
                    headers["content-type"] = value
                elif key == "CONTENT_LENGTH":
                    headers["content-length"] = value
                elif key.startswith("HTTP_"):
                    headers[key[5:].lower().replace("_", "-")] = value
                elif key == "QUERY_STRING" and value:
                    # Cannot use request.GET here because need
                    # unescaped values
                    pairs = value.split("&")
                    querydict = dict(pair.split("=") for pair in pairs)

            kwargs = {
                "method": request.method,
                "path": request.path,
                "query": querydict,
                "headers": headers,
                "body": request.body
            }
            if not verifier.verify(**kwargs):
                return JsonResponse(status=401,
                                    data={"message": "Bad signature"})

            return f(request, *args, **kwds)
        return wrapper
    return decorator
