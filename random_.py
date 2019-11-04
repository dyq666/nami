"""随机数

## 随机数类别以及性质

类别    | 性质 (短)  | 性质 (长)
-      | -         | -
弱伪随机 | 随机性     | 不存在统计学偏差, 是完全杂乱的数列
强伪随机 | 不可预测性  | 不能从过去的数列推测出下一个数
真随机   | 不可重现性 | 除非将数列本身保存下来, 否则不能重现相同的数列

越往下等级越高, 并且高等级的随机数具备所有低等级随机数的性质.


## 伪随机数生成器

仅靠软件是无法生成真随机数的, 因为运行软件的计算机本身只具备有限的内部状态,
当内部状态相同时, 必定生成相同的随机数. 虽然一个周期可能很长, 但总归还是有限的.

伪随机数生成器内部会存放一些数据, 这些数据被称为内部状态. 随机数就是依靠内部状态生成的. 生成随机数后,
伪随机数生成器也会改变内部状态. 随机数种子是用来初始化内部状态, 因此同样的随机数种子, 会产生同样的内部状态.
流程图如下:

```
     初始化内部状态          生成随机数
种子      ->      内部状态     ->     随机数
                             <-
                          改变内部状态
```

### 线性同余法

公式如下, 其中 A, C, M 是提前设置好的常量, 满足 A < M, C < M 即可.
具体实现见 `LinearCongruentialRandom`.

```
    R0 = (A * seed + C) mod M
    R1 = (A * R0 + C) mod M
    ...
    Rn = (A * R(n-1) + C) mod M
```

假设 A = 3, C = 0, M = 7, seed = 6, 那么生成的数列是 451326 的循环, 具体可以运行 `LinearCongruentialRandom.sample`.
如果选择合适的 A, C, M 的值, 可以让数列的周期变得很大. 但攻击者依然可以根据随机数和线性同余法的公式推测出 A, C, M 的值,
因此不满足强伪随机数.

### 单向散列函数法

公式如下, 其中 sha256 可以替换成任意一种单向散列函数. 具体实现见 `HashRandom`.

```
    R0 = sha256(seed)
    R1 = sha256(seed + 1)
    ...
    Rn = sha256(seed + n)
```

由于单向散列函数具有单向性, 攻击者很难根据值反推计数器的值, 因此满足强伪随机性.

### 密码法

公式如下, 其中 aes 可以替换成任意一种密码加密算法, 具体实现见 `CryptoRandom`.

```
    R0 = aes(seed)
    R1 = aes(seed + 1)
    ...
    Rn = aes(seed + n)
```

由于密码的机密性, 只要攻击者不能获取密钥就不能预测随机数, 因此满足强伪随机性.

## 如何为密码学提供随机数

在密码学中, 必须采用 >= 强伪随机数等级的生成器, 因为弱伪随机数可被预测, 可能会被攻击者获取密钥等关键数据.

真随机数生成器由于依赖物理上的随机事件, 使用成本过高, 因此大部分情况只需使用强伪随机数生成器即可.
由于不用实时生成大量的随机数种子, 因此可以选用真随机数生成器生成种子. 又因为不需要实时性, 可以事先预备一个真随机数池,
定时更新真随机数. 使用者只需要从池子中获取即可, 例如 linux 中, /dev/random 中就是一个真随机数池.

## Python 中的随机数

`random` 模块采用梅森旋转算法 (Mersenne twister), 这个算法和线性同余法类似, 是一个弱伪随机数生成器.
具体见 [Python 官方文档](https://docs.python.org/3/library/random.html#module-random), 文档中
搜索 Mersenne twister 即可.

`secrets` 模块提供用于密码学的随机数.
具体见 [Python 官方文档](https://docs.python.org/3/library/secrets.html#module-secrets)
"""

__all__ = (
    'CryptoRandom',
    'LinearCongruentialRandom',
    'HashRandom',
)

from hashlib import sha256

from aes import AES


class LinearCongruentialRandom:

    """伪随机数生成器 with 线性同余"""

    def __init__(self, a, c, m):
        self.a = a
        self.c = c
        self.m = m
        self.state = 0

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

    """伪随机数生成器 with 单向散列函数"""

    def __init__(self):
        self.state = 0

    def seed(self, value: int) -> None:
        self.state = value

    def random(self) -> str:
        value = sha256(str(self.state).encode()).hexdigest()
        self.state += 1
        return value


class CryptoRandom:

    """伪随机数生成器 by 密码"""

    def __init__(self, key, iv):
        self.cipher = AES(key, iv)
        self.state = 0

    def seed(self, value: int) -> None:
        self.state = value

    def random(self) -> bytes:
        value = self.cipher.encrypt(str(self.state).encode())
        self.state += 1
        return value
