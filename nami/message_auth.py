"""消息认证码.

主要用途是辨别消息是否被篡改, 消息是否发送自正确的发送者.

目前比较常用的是 HMAC. (`import hmac`)

主要原理是只让有密钥的人才能将数据压缩成更小的数据 (MAC 值), 相同密钥和相同数据的 MAC 值才能相同,
其余情况均不同.
"""

__all__ = (
    'HmacWithSha256',
)

import hashlib

from nami.util import Binary


class HmacWithSha256:
    """使用 sha256 的 HMAC."""

    block_size = hashlib.sha256().block_size

    @classmethod
    def digest(cls, key: bytes, msg: bytes) -> bytes:
        if len(key) > cls.block_size:
            key = hashlib.sha256(key).digest()
        key = key + b'\x00' * (cls.block_size - len(key))
        ipad = bytes([54] * cls.block_size)
        opad = bytes([92] * cls.block_size)
        inner_xor = Binary.bytes_xor(key, ipad)
        outer_xor = Binary.bytes_xor(key, opad)
        hash1 = hashlib.sha256(inner_xor + msg).digest()
        hash2 = hashlib.sha256(outer_xor + hash1).digest()
        return hash2
