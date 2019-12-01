"""分组密码的模式

ECB (Electronic CodeBook), 所有明文分组独自加密.

CBC (Cipher Block Chaining), 前一个密文分组与当前的明文分组 XOR 后再加密.

CFB (Cipher FeedBack), 前一个密文分组加密后再与当前的明文分组 XOR.

OFB (Output FeedBack), 从 iv 开始无限加密, 每次加密后的结果与明文分组 XOR.

CTR (Counter), 每次加密计数器后的结果与明文分组 XOR.

目前只有 ECB 是不能被使用的, 其他均可使用, 但使用最多的是 CBC.
```
"""

__all__ = (
    'AES',
)

import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

backend = default_backend()


class AES:
    """AES 加密, 解密."""

    BLOCK_SIZE = 16

    def __init__(self, mode, key: bytes = None):
        key = secrets.token_bytes(32) if key is None else key
        self.cipher = Cipher(
            algorithm=algorithms.AES(key),
            mode=mode,
            backend=backend,
        )

    def encrypt(self, msg: bytes) -> bytes:
        """加密."""
        encryptor = self.cipher.encryptor()
        return encryptor.update(msg) + encryptor.finalize()

    def decrypt(self, msg: bytes) -> bytes:
        """解密."""
        decryptor = self.cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()
