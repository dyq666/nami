"""对称密码.

对称密码中加密和解密使用同一个密钥.

目前安全和最常用的是 AES.

demos:
  - P47 编码 midnight. `encode_midnight`
  - P47 测验一, 凯撒密码平移 3 个字母. `caesar_cipher`
  - P47 XOR 运算规则. `xor_rule`
  - P48 比特序列的 XOR. `bit_xor`
  - P50 一次性密码本. `OneTimePad`
  - P54 Feistel 网络. `Feistel`
  - P61 三重 DES. `TripleDES`
"""

__all__ = (
    'Feistel',
    'OneTimePad',
    'TripleDES',
)

import secrets
from typing import Tuple

from nami.util import Binary

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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

    @staticmethod
    def generate_key(length) -> bytes:
        return secrets.token_bytes(length)


class Feistel:
    """Feistel 网络的简化版.

    在简化版中有如下的规则:
      1. 明文长度必须被 2 整除.
      2. 密钥长度是明文长度的一半.
      3. 轮转算法 `algorithm` 必须返回 `bytes` 类型, 并且输出的长度必须大于等于明文长度的一半.
      4. 所有子密钥相同.
    """

    def __init__(self, key: bytes, count: int, algorithm: callable):
        self.count = count
        self.key = key
        self.algorithm = algorithm

    def round(self, l: bytes, r: bytes) -> Tuple[bytes, bytes]:
        """一轮."""
        new_l = Binary.bytes_xor(self.algorithm(self.key, r), l)
        return new_l, r

    def encrypt(self, msg: bytes) -> bytes:
        if len(msg) % 2 != 0:
            raise ValueError

        # 由于每次循环都会 `reverse`, 但第一轮是不需要 `reverse`,
        # 因此第一轮前先 `reverse` 一次, 抵消掉循环中的 `reverse`.
        group = msg[len(msg) // 2:], msg[:len(msg) // 2]
        for i in range(self.count):
            group = reversed(group)
            group = self.round(*group)
        return b''.join(group)

    decrypt = encrypt

    @staticmethod
    def generate_key(length: int) -> bytes:
        return secrets.token_bytes(length)


class TripleDES:
    """三重 DES."""

    BLOCK_SIZE = 8  # algorithms.TripleDES.block_size / 8

    def __init__(self, key: bytes, iv: bytes):
        self.cipher = Cipher(
            algorithm=algorithms.TripleDES(key),
            mode=modes.CBC(iv),
            backend=default_backend(),
        )
        self.padding = padding.PKCS7(algorithms.AES.block_size)

    def encrypt(self, msg: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        padder = self.padding.padder()
        msg = padder.update(msg) + padder.finalize()
        return encryptor.update(msg) + encryptor.finalize()

    def decrypt(self, msg: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        unpadder = self.padding.unpadder()
        msg = decryptor.update(msg) + decryptor.finalize()
        return unpadder.update(msg) + unpadder.finalize()

    @classmethod
    def generate_key(cls) -> Tuple[bytes, bytes]:
        return secrets.token_bytes(24), secrets.token_bytes(cls.BLOCK_SIZE)
