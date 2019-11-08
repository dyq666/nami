import base64
import secrets
import pytest

from base64_ import b64decode, b64encode
from block import AESMode
from rsa import Mod12
from symmetric import Feistel, OneTimePad

"""test for block.py"""


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


"""test for symmetric.py"""


def test_oneTimePad():

    plaintext = '带带我'.encode()
    ciphertext, key = OneTimePad.encrypt(plaintext)
    assert OneTimePad.decrypt(ciphertext, key) == plaintext


def test_Feistel():
    feistel = Feistel(10)
    plaintext = 'ab'.encode()

    ciphertext = feistel.encrypt(plaintext)
    assert feistel.decrypt(ciphertext) == plaintext


"""test for rsa.py"""


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


"""test for base64_.py"""


@pytest.mark.parametrize('str_', (
    'A',
    'AB',
    'ABC',
    'ABCD',
    'ABCDE',
    'ABCDEF',
    'ABCDEFG',
    'ABCDEFGH',
    'dsadAb3CD231---k==.',
    '大赛的cvce1',
))
def test_base64(str_):
    bytes_ = str_.encode()
    assert b64encode(bytes_) == base64.b64encode(bytes_)

    b64 = base64.b64encode(bytes_)
    assert b64decode(b64) == base64.b64decode(b64)


"""test for binary"""


def test_base_system():
    # 2  base - 0b
    # 8  base - 0
    # 16 base - 0x
    assert int('0b1111', 2) == 15
    assert int('017', 8) == 15
    assert int('15', 10) == 15
    assert int('15') == 15
    assert int('0xf', 16) == 15


def test_binary_operation():
    # 左移, 右移
    # 二进制左移等于 * 2
    # 二进制右移等于 // 2 (如果最后一位是 1, 会被丢弃, 因此是 //)
    assert 1 << 100 == 1 * (2 ** 100)
    assert 15 >> 1 == 15 // (2 ** 1)
    assert 15 >> 2 == 15 // (2 ** 2)
    assert bin(int('0b1111', 2) >> 1) == '0b111'
    assert bin(int('0b1111', 2) >> 2) == '0b11'
    assert bin(int('0b111', 2) << 1) == '0b1110'
    assert bin(int('0b11', 2) << 2) == '0b1100'

    # 且, 或, 或非
    assert bin(int('0b1100', 2) & int('0b1010', 2)) == '0b1000'
    assert bin(int('0b1100', 2) | int('0b1010', 2)) == '0b1110'
    assert bin(int('0b1100', 2) ^ int('0b1010', 2)) == '0b110'

    # 取反
    assert ~8 == -9
    assert ~-8 == 7
    # Python 中没有符号位使用 '-' 号表示.
    # 补码计算规则: 正数的补码等于原码, 负数的补码等于原码逐位取反 (符号位不取反), 末位 + 1.
    #         计算补码         按位取反        转为原码
    # 01000    ->      01000    ->   10111    ->     11001 (末位 - 1, 逐位取反)
    # 11110    ->      10010    ->   01101    ->     01101
    assert ~int('1000', 2) == int('-1001', 2)
    assert ~int('-1110', 2) == int('1101', 2)


def test_binary_usage():
    """
    '|'
    0 0 -> 0
    0 1 -> 1
    1 0 -> 1
    1 1 -> 1

    '&'
    0 0 -> 0
    0 1 -> 0
    1 0 -> 0
    1 1 -> 1

    '^'
    0 0 -> 0
    0 1 -> 1
    1 0 -> 1
    1 1 -> 0

    假设左列是我们的影响数据, 右列是原始数据. 现在需求是我们造一个影响数据, 一个影响数据只能改变
    原始数据某位的值.

    1.
    例如我们希望将 10101 的第四位变为 1.
    这时我们可以看见 '|' 操作表中, 0 不会改变原始数据, 1 无论什么情况都会让原始数据变为 1.
    因此我们需要构造出 01000 这样的修改数据, 而 1000 = 1 << 3.

    2.
    又例如我们希望将 10101 的第三位变为 0.
    那么可以使用 '&' 操作表中, 1 不会改变原始数据, 0 无论什么情况都会让原始数据变为 0.
    因此我们需要构造出 11011 这样的修改数据. 11011 = ~100 = ~(1 << 2), 前两位可以看做符号位

    3.

    """
    raw_bits = int('10101', 2)

    assert raw_bits | int('1000', 2) == int('11101', 2)
    assert raw_bits | (1 << 3) == int('11101', 2)

    # 10101 的补码是 11011, 而 10101 在 Python 中表示为 -0101
    assert raw_bits & int('11011', 2) == int('10001', 2)
    assert raw_bits & int('-0101', 2) == int('10001', 2)
    assert raw_bits & ~(1 << 2) == int('10001', 2)

    assert raw_bits ^ int('11010', 2) ^ int('11010', 2) == raw_bits
