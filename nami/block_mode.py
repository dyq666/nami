"""分组密码的模式

ECB (Electronic CodeBook) 模式, 所有明文分组独自加密.

CBC (Cipher Block Chaining) 模式, 前一个密文分组与当前的明文分组 XOR 后再加密.
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
