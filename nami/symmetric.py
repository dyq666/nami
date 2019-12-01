"""对称密码.

### Feistel 网络

Feistel 网络用于 DES 等算法, 加密的每一步称为轮 (round), 整个加密过程就是运算多个轮.
下面是文字版流程图, 其中简化了子密钥和轮函数. 由于利用了 XOR 的特性, Feistel 网络加密和解密的步骤相同.

```
两轮

加密

L: zoe      zoe1      bob        bob1

       ↑XOR       ↑↓        ↑XOR

R: bob  ->  bob       zoe1   ->  zoe1

解密

L: bob1        bob      zoe1       zoe

         ↑XOR       ↑↓       ↑XOR

R: zoe1   ->   zoe1     bob   ->   bob


三轮

加密

L: zoe      zoe1      bob        bob1      zoe1      zoe2

       ↑XOR       ↑↓        ↑XOR       ↑↓        ↑XOR

R: bob  ->  bob       zoe1   ->  zoe1      bob1       bob1

解密

L: zoe2      zoe1    bob1        bob      zoe1       zoe

        ↑XOR      ↑↓       ↑XOR       ↑↓       ↑XOR

R: bob1  ->  bob1    zoe1   ->   zoe1     bob   ->   bob
```

代码实现参考 `Feistel`, 其中简化了轮函数, 密钥和明文长度. 实际上轮函数可以是任意的算法, 因此算法就是返回自己本身
也是有效的. 密钥全部使用一个固定值也可以看作是一个极端情况, 只不过加密和解密是使用的子密钥顺序应该相反,
这部分内容没有体现在代码中. 明文长度也为了简单起见, 这里每一次只能加密 2 字节.

## DES

全称: Data Encryption Standard

目前 DES 已经不安全了, 不应该再使用.

DES 以 64 bit 为单位加密明文, 密钥每 7 bit 会设置 1 bit 的错误检查位. 因此真正加密的是 56 bit.

DES 使用 Feistel 网络

## AES

全称: Advanced Encryption Standard

是为了取代前任标准 (DES) 出现的一个新标准, 新标准的算法由全世界的企业家和密码学家共同提供并选出, 最终
Rijndael 被选中.

Rinjndael 算法的分组长度和密钥长度可以在 [128, 256] 范围内并整除 32 的长度. 而 AES 标准中选择了
分组长度 128, 密钥长度 128, 192, 256. 单位 bit.

Rinjndael 算法也是有多个轮组成, 使用的是 SPN 结构. 可能其中逻辑比较复杂, 书中并没有详细的介绍.
其中也是用到了与密钥 XOR 这步.

Rinjndael 是可以写成公式的, 也就是只要不能在数学上对算法进行破解, 算法就是安全的.
"""

__all__ = (
    'Feistel',
    'OneTimePad',
)

import secrets
from typing import Tuple

from util import Binary


class OneTimePad:
    """一次性密码本.

    其中 key 的长度等于明文的长度.
    """

    @staticmethod
    def encrypt(msg: bytes) -> Tuple[bytes, bytes]:
        key = bytes([secrets.choice(range(0, 256)) for _ in range(len(msg))])
        return Binary.bytes_xor(key, msg), key

    @staticmethod
    def decrypt(msg: bytes, key: bytes) -> bytes:
        return Binary.bytes_xor(key, msg)


class Feistel:

    """Feistel 网络"""

    def __init__(self, count: int):
        self.count = count
        self.key = 255
        self.algorithm = lambda x: x

    def round(self, l, r):
        new_l = self.algorithm(self.key ^ r) ^ l
        return new_l, r

    def encrypt(self, plaintext: bytes) -> bytes:
        group = list(plaintext)
        for i in range(self.count):
            if i != 0:
                group = reversed(group)
            group = self.round(*group)
        return bytes(group)

    decrypt = encrypt
