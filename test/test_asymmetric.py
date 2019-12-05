from nami.asymmetric import Mod12


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
