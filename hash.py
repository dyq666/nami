"""单向散列函数.

比较消息是否相同可以改为比较他们的 "指纹" 是否相同. 这个 "指纹" 就是由单向散列函数生成的散列值,
一个单向散列函数只会计算出固定长度的散列值, 例如 `hashlib.sha256` 计算出的散列值就是 256 bit (代码如下).

```python
import hashlib

assert len(hashlib.sha256().digest()) == 256 / 8
```

碰撞性.
比较两个消息的散列值是否相同被称为完整性检查.
两个消息产生同一个散列值的情况被称为碰撞 (collision).
如果要将单向散列函数用于完整性检查, 则需要确保在事实上不可能被认为地发现碰撞.
符合这种性质的称为抗碰撞性 (collision resistance).
某条消息有相同散列值的另一条消息 - 弱抗碰撞性
找到散列值相同的两条不同消息 - 强抗碰撞性
无法设计出完全不存在碰撞的散列函数. 因为散列值的大小是固定的, 假设某个散列函数的散列值
固定为 4 bit 长度. 那么散列值最多只有 16 种, 也就是当第 17 个东西出现时必定产生碰撞.

单向性.
散列值无法反推消息. 就像我们只能两个指纹去比较, 不能用一个指纹反推出整个人.
单向性在密码学中是正向的受益, 但在有的时候可能是负向的受益, 有的时候根据散列值
反推消息可能是很有用的. (但是目前没有散列函数具备双向性的).

应用.
截止到目前为止, 单向散列函数总共有两种性质: 碰撞性和单向性. 不同的应用场景可能只依赖于其中一种性质.
当然也可以直接选当下最安全的 SHA-2.

函数种类.
MD 系列, MD4, MD5 目前都不具备碰撞性了.
SHA 系统, sha1 目前不具备碰撞性, sha224, sha256, sha512 等都属于 SHA-2, 后面的数字
代表散列值的长度. 例如 sha256 就是 256 bit, 目前使用 sha256 是最优的. 目前还有最新的 SHA-3.
SHA-3 的优点是可以生成任意长度的散列值以及输入任意长度的消息, 例如 SHA-2 的输入长度就是 2**128 - 1,
输出长度都是固定的.
"""

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
        seq = [1.0] + [number for number in range(y, y - n, -1)]
        not_same_p = reduce(mul, seq)
        return 1 - not_same_p

    probability_365 = partialmethod(probability, 365)
