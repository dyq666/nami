import secrets

import pytest
from cryptography.hazmat.primitives.ciphers import modes

from nami.block_mode import AES
from nami.util import Binary


class TestAESMode:

    @pytest.fixture
    def key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def iv(self):
        return secrets.token_bytes(AES.BLOCK_SIZE)

    def test_ecb_mode(self, key):
        aes = AES(modes.ECB(), key)

        # 如果明文分组相同, 那么密文分组也相同, 并且和单独加密明文分组的值一样.
        msg = b'1' * AES.BLOCK_SIZE * 2
        ciphertext = aes.encrypt(msg)
        assert ciphertext[:AES.BLOCK_SIZE] == ciphertext[AES.BLOCK_SIZE:]
        assert ciphertext[:AES.BLOCK_SIZE] == aes.encrypt(b'1' * AES.BLOCK_SIZE)

        # `msg` 的长度必须是 `AES.BLOCK_SIZE` 的倍数.
        msg = b'1'
        with pytest.raises(ValueError):
            aes.encrypt(msg)

    def test_cbc_mode(self, key, iv):
        # 明文分组相同, 密文分组不同.
        aes = AES(modes.CBC(iv), key=key)
        plain_1, plain_2 = b'1' * AES.BLOCK_SIZE, b'1' * AES.BLOCK_SIZE
        ciphertext = aes.encrypt(plain_1 + plain_2)
        cipher_1, cipher_2 = ciphertext[:AES.BLOCK_SIZE], ciphertext[AES.BLOCK_SIZE:]
        assert cipher_1 != cipher_2
        # 第一组加密的结果作为第二组的 iv 对第二组加密, 和两组一起加密的结果相同.
        aes = AES(modes.CBC(cipher_1), key=key)
        assert aes.encrypt(plain_1) == cipher_2

        # `msg` 的长度必须是 `AES.BLOCK_SIZE` 的倍数.
        msg = b'1'
        with pytest.raises(ValueError):
            aes.encrypt(msg)

        # 先与前一组 xor 后加密.
        msg = b'1' * AES.BLOCK_SIZE
        msg1 = Binary.bytes_xor(msg, iv)
        assert AES(modes.CBC(iv), key=key).encrypt(msg) == AES(modes.ECB(), key=key).encrypt(msg1)

    def test_cfb_mode(self, key, iv):
        # `msg` 的长度可以是任意长度
        aes = AES(modes.CFB(iv), key)
        assert aes.encrypt(b'1')

        # 前一组先加密再 xor.
        iv = secrets.token_bytes(AES.BLOCK_SIZE)
        key = secrets.token_bytes(32)
        cfb = AES(modes.CFB(iv), key=key)
        ecb = AES(modes.ECB(), key=key)
        msg1, msg2 = b'1' * AES.BLOCK_SIZE, b'2' * AES.BLOCK_SIZE
        cipher = cfb.encrypt(msg1 + msg2)
        cipher1, cipher2 = cipher[:AES.BLOCK_SIZE], cipher[AES.BLOCK_SIZE:]
        assert cipher1 == Binary.bytes_xor(ecb.encrypt(iv), msg1)
        assert cipher2 == Binary.bytes_xor(ecb.encrypt(cipher1), msg2)

    def test_ofb_mode(self, key, iv):
        # `msg` 的长度可以是任意长度
        aes = AES(modes.OFB(iv), key)
        assert aes.encrypt(b'1')

        # 前一组先加密再 xor.
        iv = secrets.token_bytes(AES.BLOCK_SIZE)
        key = secrets.token_bytes(32)
        cfb = AES(modes.OFB(iv), key=key)
        ecb = AES(modes.ECB(), key=key)
        msg1, msg2 = b'1' * AES.BLOCK_SIZE, b'2' * AES.BLOCK_SIZE
        cipher = cfb.encrypt(msg1 + msg2)
        cipher1, cipher2 = cipher[:AES.BLOCK_SIZE], cipher[AES.BLOCK_SIZE:]
        key1 = ecb.encrypt(iv)
        key2 = ecb.encrypt(key1)
        assert cipher1 == Binary.bytes_xor(key1, msg1)
        assert cipher2 == Binary.bytes_xor(key2, msg2)
