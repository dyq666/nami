import hashlib
import hmac
import secrets

from nami.message_auth import HmacWithSha256


def test_hmac_with_sha256():
    keys = [secrets.token_bytes(i) for i in range(63, 66)]
    msg = '带带我'.encode()
    for key in keys:
        assert HmacWithSha256.digest(key, msg) == hmac.digest(key, msg, hashlib.sha256)
