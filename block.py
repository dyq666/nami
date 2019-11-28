"""分组密码的模式

只能加密固定长度的算法, 如果要变成加密任意长度的算法, 就需要选择一种迭代的模式.
例如对称加密中的 DES, AES 就是这种, 统称分组密码. 与之相反的就是流密码例如一次性密码本.

## ECB 模式 (Electronic CodeBook)

流程如下, 每个明文分组都分开加密, 由于使用的算法和密钥都是一样的, 因此
相同的明文分组会得到相同的密文分组. 攻击者可以根据密文分组出现的频率来获取
一些明文的线索.

```
明文分组1   明文分组2   明文分组3

   ↓ 加密    ↓ 加密     ↓ 加密

密文分组1   密文分组2   密文分组3
```

## CBC 模式 (Cipher Block Chaining)

流程如下, 每个明文分组都需要与前一个密文 XOR 后再加密.

```
         明文分组1        明文分组2     明文分组3

   ↑   →   ↓ XOR   ↑  →  ↓ XOR   ↑  →  ↓ XOR

   ↑       ↓ 加密   ↑     ↓ 加密   ↑     ↓ 加密

初始化向量     密文分组1      密文分组2     密文分组3

初始化向量实际上就是一个虚假的密文分组, 需要和密文分组保持一致的大小. 因此在 AES
中初始化向量应该是 16 字节.

CBC 模式下, 任意一个明文分组不正确, 都会影响后面所有的解密.
```
"""

__all__ = (
    'AES',
    'AESMode',
)

import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from util import fill_seq


class AESMode:

    def __init__(self, key: bytes):
        self.key = key

    def ecb_encrpty(self, plaintext: bytes) -> bytes:
        mode = modes.ECB()
        return self._encrypt(plaintext, mode)

    def cbc_encrpty(self, plaintext: bytes, iv: bytes) -> bytes:
        mode = modes.CBC(iv)
        return self._encrypt(plaintext, mode)

    def _encrypt(self, plaintext: bytes, mode) -> bytes:
        plaintext = self.filler(plaintext)
        cipher = Cipher(
            algorithm=algorithms.AES(self.key),
            mode=mode,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    @staticmethod
    def filler(text: bytes) -> bytes:
        # aes 加密的明文字节数必须能被 16 整除
        bytes_size = algorithms.AES.block_size // 8
        return fill_seq(text, size=bytes_size, filler=b'\x01')

    @staticmethod
    def gen_key() -> bytes:
        # aes 密钥长度只能是 16, 24, 32, (单位: 字节)
        return secrets.token_bytes(32)


class AES:

    BLOCK_BYTES_SIZE = algorithms.AES.block_size // 8

    def __init__(self, key: bytes, iv: bytes):
        """len(iv) == 16 == algorithms.AES.block_size / 8"""
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def encrypt(self, content: bytes) -> bytes:
        """
        加密前将内容填充, 使其可以被 16 整除. 且填充字符是填充大小对应的 unicode.
        此外, 如果内容本身已可被 16 整除, 也需要补上 16 个填充字符.
        """
        filler_len = self.BLOCK_BYTES_SIZE - (len(content) % self.BLOCK_BYTES_SIZE)
        content += chr(filler_len).encode() * filler_len
        encryptor = self.cipher.encryptor()
        return encryptor.update(content) + encryptor.finalize()

    def decrypt(self, content: bytes) -> bytes:
        """
        加密后的最后一个字符一定是填充字符, 根据此填充字符可以删去填充字符序列.
        """
        decryptor = self.cipher.decryptor()
        msg = decryptor.update(content) + decryptor.finalize()
        filler_len = msg[-1]
        return msg[:-filler_len]
