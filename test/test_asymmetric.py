from nami.asymmetric import Mod12, KeyCenter


def test_KeyCenter():
    """模拟一次 alice 和 bob 的通信."""
    alice, bob = 'alice', 'bob'

    # 会话中心生成会密钥s
    session_key = KeyCenter.generate_session_key()
    # 取出 alice 和 bob 的密钥
    alice_key = KeyCenter.get_key(alice)
    bob_key = KeyCenter.get_key(bob)
    # 用 alice 和 bob 的密钥加密会话密钥
    to_alice_key = KeyCenter.encrypt(alice_key, session_key)
    to_bob_key = KeyCenter.encrypt(bob_key, session_key)

    # alice 解密获得会话密钥
    assert KeyCenter.decrypt(alice_key, to_alice_key) == session_key

    # bob 解密获得会话密钥
    assert KeyCenter.decrypt(bob_key, to_bob_key) == session_key


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
