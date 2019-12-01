"""公钥密码

1. 公钥加密, 私钥解密.

私钥存放在接收者. 公钥由接收者配送给发送者.
其他人拿不到私钥就无法解密, 因此公钥配送过程中不用担心被窃取.

2. mod 运算

我们可以比较容易实现 mod 世界中的 `加 减 乘 除 乘方` 运算 (具体实现在 Mod12), 其中:
减法可以转换成加法, 除法可以转换成乘法, 但求对数很难转成乘法, 在数学上这种问题叫求离散对数.
而 RSA 就利用了数学上求离散对数非常困难的特性设计了算法.

3. RSA 算法

### 加密解密公式

加密: 密文 = (明文 ** E) % N, 因此, E 和 N 就是公钥

解密: 明文 = (密文 ** D) % N, 因此, D 和 N 就是私钥

### 生成密钥对

其中 lcm 是求最小公倍数, gcd 是求最大公约数

1. 随机选择两个大质数 p, q

2. N = p * q

3. L = lcm(p-1, q-1)

4. E 需要满足条件: 1 < E < L 和 gcd(E, L) = 1

5. D 需要满足条件: 1 < D < L 和 (E * D) % L = 1

### 攻击 RSA

窃听者可以获取到, E, N, 密文, 如果要获取明文可以破解以下途径:

1. 根据加密公式: `密文 = (明文 ** E) % N`, 总共三个变量求未知变量明文.

   求未知变量实际等价于求离散对数, 但目前没有求离散对数的高效算法.

2. 暴力破解, 根据书中的说法, 目前 p 和 q 的长度均 > 1024 bit, N > 2048 bit, D 和 N 长度类似,

   因此要运行 2 ** 2048 次才能全遍历一次.

3. 根据生成密钥对步骤五中公式: `(E * D) % L = 1`, 由于式子中存在另一个未知变量 L, 问题因此转为求 L.

   L 又由 p, q 计算出, 而 p, q 又是质数, 所以问题又变为求 N 的质因数分解. 但目前没有求质因素的高效算法.

4. 根据生成密钥对步骤一中的伪随机数算法, 如果伪随机数生成器算法很差, 那么密码破译这就可能推测出 p, q

因此在目前的环境下窃听者很难根据 E, N, 密文来获取明文.
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
