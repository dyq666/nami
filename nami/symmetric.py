"""对称密码.

对称密码中加密和解密使用同一个密钥.

目前安全和最常用的是 AES.
"""

__all__ = (
    'Feistel',
    'OneTimePad',
)

import secrets
from typing import Tuple

from util import Binary


class OneTimePad:
    """一次性密码本.

    其中 key 的长度等于明文的长度.
    """

    @staticmethod
    def encrypt(msg: bytes) -> Tuple[bytes, bytes]:
        key = bytes([secrets.choice(range(0, 256)) for _ in range(len(msg))])
        return Binary.bytes_xor(key, msg), key

    @staticmethod
    def decrypt(msg: bytes, key: bytes) -> bytes:
        return Binary.bytes_xor(key, msg)


class Feistel:
    """Feistel 网络的简化版.

    在简化版中有如下的规则:

      1. key 的值固定是 255, 因此长度是 1 字节.
      2. 明文必须是 2 字节长度.
      3. 轮转算法固定为 y = x.
    """

    def __init__(self, count: int):
        self.count = count
        self.key = 255
        self.algorithm = lambda x: x

    def round(self, l, r):
        new_l = self.algorithm(self.key ^ r) ^ l
        return new_l, r

    def encrypt(self, msg: bytes) -> bytes:
        group = list(msg)
        for i in range(self.count):
            if i != 0:
                group = reversed(group)
            group = self.round(*group)
        return bytes(group)

    decrypt = encrypt
