"""公钥密码.

公钥加密, 私钥解密. 私钥存放在接收者. 公钥由接收者配送给发送者.

目前常用的是 rsa.
"""

from typing import Optional


class Mod12:

    """mod 12 的世界只有 0 - 11"""

    def __init__(self, value: int):
        if value >= 12:
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
        1. y + y' = 0
        2. x - y = x + y'

        根据上面的式子我们可以将减法转换成加法.

        枚举 y 等于 [0, 11] 找到符合式子 1 中的 y' 值
        可以发现: 除了 0 的 y' 是 0 以外其他 y' = 12 - y
        具体可以看 `Mod12.search_sub`
        """
        value = 0 if other.v == 0 else (12 - other.v)
        return self + type(self)(value)

    def __mul__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v * other.v) % 12
        return type(self)(value)

    def __truediv__(self, other: 'Mod12') -> Optional['Mod12']:
        """
        根据 Mod12.search_truediv 的结果来看, 只有 1, 5, 7, 11 可以将除法转乘法
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
