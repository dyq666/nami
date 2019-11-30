import secrets

from nami.block_mode import AESMode


class TestAESMode:

    def test_ecb_mode(self):
        key = AESMode.gen_key()
        aes = AESMode(key)
        plaintext = b'1' * 32
        ciphertext = aes.ecb_encrpty(plaintext)
        # 两组内容相同都是 b'1....', 加密后相同.
        assert ciphertext[:len(ciphertext) // 2] == ciphertext[len(ciphertext) // 2:]

    def test_cbc_mode(self):
        key = AESMode.gen_key()
        iv = secrets.token_bytes(16)
        aes = AESMode(key)

        plain_l, plain_r = b'1' * 16, b'1' * 16
        ciphertext = aes.cbc_encrpty(plain_l + plain_r, iv)
        cipher_l, cipher_r = ciphertext[:len(ciphertext) // 2], ciphertext[len(ciphertext) // 2:]
        # 两组内容相同都是 b'1....', 加密后不同.
        assert cipher_l != cipher_r

        # 第一组加密的结果作为第二组的 iv 对第二组加密, 和两组一起加密的结果相同
        assert aes.cbc_encrpty(plain_r, cipher_l) == cipher_r
