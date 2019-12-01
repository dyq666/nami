"""随机数.
"""

__all__ = (
    'LinearCongruentialRandom',
    'HashRandom',
)

from datetime import datetime
from hashlib import sha256


class LinearCongruentialRandom:
    """伪随机数生成器 with 线性同余."""

    def __init__(self, a, c, m):
        self.a = a
        self.c = c
        self.m = m
        self.state = int(datetime.now().timestamp())

    def seed(self, value: int) -> None:
        self.state = value

    def random(self) -> int:
        value = (self.a * self.state + self.c) % self.m
        self.state = value
        return value

    @classmethod
    def sample(cls):
        r = cls(3, 0, 7)
        r.seed(6)
        for i in range(0, 100, 6):
            print(''.join(str(r.random()) for _ in range(6)))


class HashRandom:
    """伪随机数生成器 with 单向散列函数."""

    def __init__(self):
        self.state = int(datetime.now().timestamp())

    def seed(self, value: int) -> None:
        self.state = value

    def random(self) -> str:
        value = sha256(str(self.state).encode()).hexdigest()
        self.state += 1
        return value
