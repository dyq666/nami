"""公钥密码.

demo:
  - P105 密钥中心. `KeyCenter`
  - P110 时钟运算. `Mod12`

RSA 的最终实现可以用于生产环境, 所以放到了:
https://github.com/dyq666/sanji/blob/master/util/third_cryptography.py
"""

import secrets
from typing import Optional

from nami.util import Binary


class KeyCenter:
    """密钥中心.

    假设 `keys` 是存储密钥的数据库, 加密算法是 XOR.
    """

    keys = {
        'alice': b'\xc3\xb4',
        'bob': b'\x18',
    }

    @classmethod
    def get_key(cls, name: str) -> bytes:
        return cls.keys.get(name)

    @staticmethod
    def encrypt(msg1: bytes, msg2: bytes) -> bytes:
        return Binary.bytes_xor(msg1, msg2)

    decrypt = encrypt

    @staticmethod
    def generate_session_key() -> bytes:
        return secrets.token_bytes(1)


class Mod12:
    """mod 12 的世界只有 0 - 11"""

    def __init__(self, value: int):
        if not 0 <= value <= 12:
            raise ValueError
        self.v = value

    def __repr__(self):
        return (
            f'<{self.__class__.__name__}'
            f' v={self.v!r}'
            f'>'
        )

    def __eq__(self, other: 'Mod12'):
        return all((
            type(self) == type(other),
            self.v == other.v
        ))

    def __add__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v + other.v) % 12
        return type(self)(value)

    def __sub__(self, other: 'Mod12') -> 'Mod12':
        """
        假设 x 是已知值, 计算 (x - y) mod12 的值.

        只要满足 (y + y') mod12 = 0, 即可将 (x - y) mod12 改为计算
        (x + y') mod12.

        采用枚举法找规律, 具体过程在 `search_sub`.
        """
        value = 0 if other.v == 0 else (12 - other.v)
        return self + type(self)(value)

    def __mul__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v * other.v) % 12
        return type(self)(value)

    def __truediv__(self, other: 'Mod12') -> Optional['Mod12']:
        """
        假设 x 是已知值, 计算 (x / y) mod12 的值.

        只要满足 (y * y') mod12 = 1, 即可将 (x / y) mod12 改为计算
        (x * y') mod12.

        采用枚举法找规律, 具体过程在 `search_truediv`.
        """
        if other.v not in {1, 5, 7, 11}:
            return
        return self * other

    def __pow__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v ** other.v) % 12
        return type(self)(value)

    @classmethod
    def search_sub(cls):
        for i in range(12):
            for j in range(12):
                x = cls(i)
                y = cls(j)
                res = x + y
                if res.v == 0:
                    print(f'{x.v:2d} + {y.v:2d} = {res.v}')

    @classmethod
    def search_truediv(cls):
        for i in range(12):
            for j in range(12):
                x = cls(i)
                y = cls(j)
                res = x * y
                if res.v == 1:
                    print(f'{x.v:2d} + {y.v:2d} = {res.v}')
