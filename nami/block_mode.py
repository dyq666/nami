"""分组密码的模式.

demo:
  - P79 ECB 模式. `test/test_block_mode/test_ecb_mode`
  - P82 CBC 模式. `test/test_block_mode/test_cbc_mode`
  - P86 小测验 4 仿 CBC 模式. `test/test_block_mode/test_fake_cbc_mode`
  - P88 CFB 模式. `test/test_block_mode/test_cfb_mode`
  - P91 OFB 模式. `test/test_block_mode/test_ofb_mode`

比较推荐的两种模式是 CBC 和 CTR. AES_CBC 和 AES_CTR 两种的详细实现在:
https://github.com/dyq666/sanji/blob/master/util/third_cryptography.py
"""

__all__ = (
    'AES',
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

backend = default_backend()


class AES:
    """AES 加密, 解密."""

    BLOCK_SIZE = 16

    def __init__(self, mode, key: bytes):
        self.cipher = Cipher(
            algorithm=algorithms.AES(key),
            mode=mode,
            backend=backend,
        )

    def encrypt(self, msg: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        return encryptor.update(msg) + encryptor.finalize()

    def decrypt(self, msg: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        return decryptor.update(msg) + decryptor.finalize()
