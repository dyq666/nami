"""单向散列函数.

主要用途是辨别消息是否被篡改.

目前比较安全的是 SHA 二代和三代, 例如 `from hashlib import sha256, sha3_256`.

主要原理是将数据压缩成更小的数据 (散列值) 便于快速比较, 相同数据散列值必须相同,
不同数据散列值必定不同 (理论上是不可能满足 "必定" 不同的, 因为散列值长度固定,
意味着只存在有限种数据, 但只要有限种在人类的角度上是无限种即可).
"""

__all__ = (
    'BirthdayParadox',
)

from functools import partialmethod, reduce
from operator import mul


class BirthdayParadox:
    """生日悖论."""

    @staticmethod
    def least_number(y: int, p: float) -> int:
        """假设一年有 `y` 天, 从 `n` 个人中找到两个相同生日的概率大于 `p`, 求满足条件的最小的 `n`."""
        not_same_p = 1.0
        for n, number in enumerate(range(y, 0, -1), start=1):
            not_same_p *= number / y
            if 1 - not_same_p > p:
                return n

    least_number_365 = partialmethod(least_number, 365)

    @staticmethod
    def probability(y: int, n: int) -> float:
        """假设一年有 `y` 天, 求从 `n` 个人中找到两个相同生日的概率."""
        seq = [1.0] + [number / y for number in range(y, y - n, -1)]
        not_same_p = reduce(mul, seq)
        return 1 - not_same_p

    probability_365 = partialmethod(probability, 365)
