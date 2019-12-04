"""对称密码.

对称密码中加密和解密使用同一个密钥.

目前安全和最常用的是 AES.

demos:
  - P47 编码 midnight. `encode_midnight`
  - P47 测验, 凯撒密码平移 3 个字母. `caesar_cipher`
  - P47 XOR 运算规则. `xor_rule`
  - P48 比特序列的 XOR. `bit_xor`
  - P50 一次性密码本 `OneTimePad`
"""

__all__ = (
    'Feistel',
    'OneTimePad',
)

import secrets

from nami.util import Binary


def encode_midnight():
    """编码 midnight demo."""
    s = 'midnight'
    for c in s:
        print(f'{c} -> {Binary.int_2_str(ord(c))}')


def caesar_cipher():
    """凯撒密码 demo."""
    map_ = {i: (i + 3) % 26 for i in range(26)}
    for k, v in map_.items():
        print(f'{k} -> {v}')


def xor_rule():
    """XOR 运算规则 demo."""
    group = (
        ('0', '0'),
        ('0', '1'),
        ('1', '0'),
        ('1', '1'),
    )
    for l, r in group:
        print(f'{l} XOR {r} = {Binary.str_xor(l, r)}')


def bit_xor():
    """比特序列的 XOR demo."""
    top = '01001100'
    bot = '10101010'
    line = '-' * 29
    re1 = Binary.str_xor(top, bot)
    re2 = Binary.str_xor(re1, bot)

    print(f'{" ".join(top)}  ... A')
    print(f'{" ".join(bot)}  ...       B')
    print(line)
    print(f'{" ".join(re1)}  ... A XOR B')
    print()
    print(f'{" ".join(re1)}  ... A XOR B')
    print(f'{" ".join(bot)}  ...       B')
    print(line)
    print(f'{" ".join(re2)}  ... A')


class OneTimePad:
    """一次性密码本.

    密钥长度必须与消息长度相同.
    """

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, msg: bytes) -> bytes:
        if len(msg) != len(self.key):
            raise ValueError
        return Binary.bytes_xor(self.key, msg)

    decrypt = encrypt

    @classmethod
    def generate_key(cls, length) -> bytes:
        return secrets.token_bytes(length)


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
