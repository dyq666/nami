__all__ = (
    'AESCipher',
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_BYTES_SIZE = algorithms.AES.block_size // 8


class AESCipher:

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
