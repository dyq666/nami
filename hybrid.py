"""混合密码系统

## 使用混合密码系统的原因

公钥密码有两个弊端:

1. 速度慢

2. 无法防御中间人攻击

对称密码有一个弊端:

1. 无法解决密钥配送问题

因此使用混合密码系统, 用公钥密码加密对称密码中的密钥, 用对称密码加密明文. 这就解决了公钥密码速度慢和

对称密码的密钥配送问题. 公钥密码的中间人攻击问题还需要后面解决.

"""

__all__ = (
    'Hybrid',
    'HybridHMAC',
)

import os
from typing import Tuple

from aes import AES
from mac import HMAC
from rsa import RSAPrivateKey, RSAPublicKey


class Hybrid:

    @staticmethod
    def encrypt(plaintext: bytes, public_key_pem: bytes) -> Tuple[bytes, bytes]:
        key: bytes = os.urandom(16)
        iv: bytes = os.urandom(16)
        aes = AES(key, iv)
        rsa_public = RSAPublicKey.load(public_key_pem)

        ciphertext = aes.encrypt(plaintext)
        cipherkey = rsa_public.encrypt(key + iv)
        return cipherkey, ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, private_key_pem: bytes, cipherkey) -> bytes:
        rsa_private = RSAPrivateKey.load(private_key_pem)

        plainkey = rsa_private.decrypt(cipherkey)
        key, iv = plainkey[:16], plainkey[16:]

        aes = AES(key, iv)
        plaintext = aes.decrypt(ciphertext)
        return plaintext


class HybridHMAC:

    @staticmethod
    def encrypt(plaintext: bytes, public_key_pem: bytes):
        plainkey: bytes = os.urandom(16)
        hmac = HMAC(plainkey)
        public_key = RSAPublicKey.load(public_key_pem)

        mac = hmac.encrypt(plaintext)
        cipherkey = public_key.encrypt(plainkey)
        return cipherkey, mac

    @staticmethod
    def validate(plaintext: bytes, mac: bytes,
                 private_key_pem: bytes, cipherkey) -> bool:
        rsa_private = RSAPrivateKey.load(private_key_pem)

        plainkey = rsa_private.decrypt(cipherkey)

        hmac = HMAC(plainkey)
        return mac == hmac.encrypt(plaintext)
