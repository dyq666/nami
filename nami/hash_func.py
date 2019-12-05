"""单向散列函数.

demo:
  - P158 sha256 的散列值长度. `sha256_demo`
  - P180 生日攻击. `BirthdayParadox`
"""

__all__ = (
    'BirthdayParadox',
)

import hashlib
from functools import partialmethod, reduce
from operator import mul


def sha256_demo():
    print(len(hashlib.sha256().digest()) * 8)


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
