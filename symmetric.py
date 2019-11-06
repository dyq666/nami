"""对称密码

## XOR

英文: exclusive or, 中文: 异或. 公式如下.

```
    0 XOR 0 = 0
    0 XOR 1 = 1
    1 XOR 0 = 1
    1 XOR 1 = 0
```

异或操作可以看成黑白棋的翻转. 假设 0 是白, 1 是黑, 棋子被翻转则换颜色.
又假设操作 0 是不翻转, 操作 1 是翻转. 因此上面的公式可以这样解释.

```
    白 不翻转 = 白
    白 翻转 = 黑
    黑 不翻转 = 黑
    黑 翻转 白
```

## 一次性密码本

一次性密码就是利用 XOR 对数据进行加密和解密. 假设我们将数据 A 和数据 B 做两次 XOR,
A XOR B XOR B. 也就是等价于将每位都翻转两次或不翻转两次, 最终结果就是 A 没变.
第一次 XOR 可以看做加密, 而第二次 XOR 可以看做解密, B 则是密钥.

如果选取了合适的密钥, 并且密钥没有泄露, 那么一次性密码是永远无法破解的. 假设明文是 `midnight`,
破译者使用暴力破解法对密文解密, 解密过程中会出现 `midnight` 这个词, 但同时也会出现相同位数的任意词,
例如 `mistress` 等, 破解者无法得知哪个参数真正的明文.

但是一次性密码本有很大的弊端, 导致没有被使用. XOR 是按位加密, 假设明文有 1024 位, 那么密钥
也得有 1024 位, 当然也可以加密一部分数据, 例如只加密其中的 512 位, 但加密位数越少越可能被破解,
所以实际上密钥的位数也不差明文太多. 我们用密钥加密了明文, 现在要发送密钥, 但密钥和明文大小差不多,
也就是如果我们有办法安全的发送一个密钥, 那么我们就有办法安全的发送一个和密钥大小差不多的明文, 那么
就不需要密钥了.
"""

__all__ = (
    'AES',
    'OneTimePad',
)

import secrets
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_BYTES_SIZE = algorithms.AES.block_size // 8


class OneTimePad:

    """一次性密码本"""

    @staticmethod
    def encrypt(plaintext: bytes) -> Tuple[bytes, bytes]:
        key = bytes([secrets.choice(range(0, 256)) for _ in range(len(plaintext))])
        ciphertext = bytes([byte ^ key[i] for i, byte in enumerate(plaintext)])
        return ciphertext, key

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        plaintext = bytes([byte ^ key[i] for i, byte in enumerate(ciphertext)])
        return plaintext


class AES:

    def __init__(self, key: bytes, iv: bytes):
        """len(iv) == 16 == algorithms.AES.block_size / 8"""
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def encrypt(self, content: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        filler_len = AES_BLOCK_BYTES_SIZE - (len(content) % AES_BLOCK_BYTES_SIZE)
        content += chr(filler_len).encode() * filler_len
        return encryptor.update(content) + encryptor.finalize()

    def decrypt(self, content: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        msg = decryptor.update(content) + decryptor.finalize()
        filler_len = msg[-1]
        return msg[:-filler_len]
