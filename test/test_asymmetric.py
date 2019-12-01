from nami.asymmetric import Mod12
from util import RSAPrivateKey, RSAPublicKey


class TestMod12:

    def test_add(self):
        x = Mod12(11)
        assert x + Mod12(0) == Mod12(11)
        assert x + Mod12(1) == Mod12(0)
        assert x + Mod12(2) == Mod12(1)
        assert x + Mod12(3) == Mod12(2)
        assert x + Mod12(4) == Mod12(3)
        assert x + Mod12(5) == Mod12(4)
        assert x + Mod12(6) == Mod12(5)
        assert x + Mod12(7) == Mod12(6)
        assert x + Mod12(8) == Mod12(7)
        assert x + Mod12(9) == Mod12(8)
        assert x + Mod12(10) == Mod12(9)
        assert x + Mod12(11) == Mod12(10)

    def test_sub(self):
        x = Mod12(1)
        assert x - Mod12(0) == Mod12(1)
        assert x - Mod12(1) == Mod12(0)
        assert x - Mod12(2) == Mod12(11)
        assert x - Mod12(3) == Mod12(10)
        assert x - Mod12(4) == Mod12(9)
        assert x - Mod12(5) == Mod12(8)
        assert x - Mod12(6) == Mod12(7)
        assert x - Mod12(7) == Mod12(6)
        assert x - Mod12(8) == Mod12(5)
        assert x - Mod12(9) == Mod12(4)
        assert x - Mod12(10) == Mod12(3)
        assert x - Mod12(11) == Mod12(2)

    def test_mul(self):
        x = Mod12(4)
        assert x * Mod12(0) == Mod12(0)
        assert x * Mod12(1) == Mod12(4)
        assert x * Mod12(2) == Mod12(8)
        assert x * Mod12(3) == Mod12(0)
        assert x * Mod12(4) == Mod12(4)
        assert x * Mod12(5) == Mod12(8)
        assert x * Mod12(6) == Mod12(0)
        assert x * Mod12(7) == Mod12(4)
        assert x * Mod12(8) == Mod12(8)
        assert x * Mod12(9) == Mod12(0)
        assert x * Mod12(10) == Mod12(4)
        assert x * Mod12(11) == Mod12(8)

    def test_truediv(self):
        x = Mod12(4)
        assert x / Mod12(0) is None
        assert x / Mod12(1) == Mod12(4)
        assert x / Mod12(2) is None
        assert x / Mod12(3) is None
        assert x / Mod12(4) is None
        assert x / Mod12(5) == Mod12(8)
        assert x / Mod12(6) is None
        assert x / Mod12(7) == Mod12(4)
        assert x / Mod12(8) is None
        assert x / Mod12(9) is None
        assert x / Mod12(10) is None
        assert x / Mod12(11) == Mod12(8)

    def test_pow(self):
        x = Mod12(7)
        assert x ** Mod12(0) == Mod12(1)
        assert x ** Mod12(1) == Mod12(7)
        assert x ** Mod12(2) == Mod12(1)
        assert x ** Mod12(3) == Mod12(7)
        assert x ** Mod12(4) == Mod12(1)
        assert x ** Mod12(5) == Mod12(7)
        assert x ** Mod12(6) == Mod12(1)
        assert x ** Mod12(7) == Mod12(7)
        assert x ** Mod12(8) == Mod12(1)
        assert x ** Mod12(9) == Mod12(7)
        assert x ** Mod12(10) == Mod12(1)
        assert x ** Mod12(11) == Mod12(7)


class TestRsa:

    def test_load_private_key(self):
        """load 后的 private key 应该生成一样的 public key"""
        private_key = RSAPrivateKey.generate()
        private_key2 = RSAPrivateKey.load(private_key.format_private_key())
        assert private_key.format_public_key() == private_key2.format_public_key()

    def test_encrpty_and_decrpty(self):
        content = '带带我666'.encode()
        private_key = RSAPrivateKey.generate()
        public_key = RSAPublicKey.load(private_key.format_public_key())
        assert private_key.decrypt(public_key.encrypt(content)) == content
