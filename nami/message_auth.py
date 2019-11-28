"""消息认证码.

消息认证码可以确认消息是否被篡改, 以及消息是否发送自正确的发送者.

将大数据压缩成小数据, 操作过程中需要被密钥影响, 生成的值称为 MAC.

发送者和接收者之间有密钥, 有密钥才能计算 MAC 值.

消息认证码可以由多种方式实现, 比较容易理解的一种就是在单向散列函数中加入
密钥, 例如 HMAC.
"""

__all__ = (
    'HmacWithSha256',
)

import hashlib

from util import Binary


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
