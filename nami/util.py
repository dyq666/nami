__all__ = (
    'Binary',
    'RSAPrivateKey',
    'RSAPublicKey',
    'fill_seq',
    'seq_grouper',
    'strip_seq',
)

import math
from typing import TYPE_CHECKING, Any, Iterable, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey

Seq = Union[str, bytes, list, tuple]


class Binary:
    """copy from https://github.com/dyq666/sanji"""

    xor_map = {
        ('0', '0'): '0',
        ('0', '1'): '1',
        ('1', '0'): '1',
        ('1', '1'): '0',
    }

    @classmethod
    def str_xor(cls, s1: str, s2: str) -> str:
        """XOR 两个 8 位二进制字符串."""
        if len(s1) != len(s2):
            raise ValueError

        return ''.join(cls.xor_map[item] for item in zip(s1, s2))

    @classmethod
    def bytes_xor(cls, b1: bytes, b2: bytes) -> bytes:
        """XOR 两个字节序列."""
        return bytes(item1 ^ item2 for item1, item2 in zip(b1, b2))

    @classmethod
    def str_2_bytes(cls, s: str) -> bytes:
        """将 8 位二进制字符串转为字节序列."""
        if len(s) % 8 != 0:
            raise ValueError

        return bytes(cls.str_2_int(item) for item in seq_grouper(s, 8))

    @classmethod
    def bytes_2_str(cls, b: bytes) -> str:
        """将字节序列转为 8 位二进制字符串."""
        return ''.join(cls.int_2_str(byte) for byte in b)

    @staticmethod
    def int_2_str(i: int) -> str:
        """将 [0, 255] 之间的整数转为 1 字节的 8 位二进制字符串."""
        if not 0 <= i <= 255:
            raise ValueError

        return format(i, '08b')

    @staticmethod
    def str_2_int(s: str) -> int:
        """将 1 字节的 8 位二进制字符串转为整数."""
        if len(s) != 8:
            raise ValueError

        return int(s, 2)


class RSAPrivateKey:

    def __init__(self, key: '_RSAPrivateKey'):
        self.key = key

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.key.decrypt(
            ciphertext=ciphertext,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def format_private_key(self, password: Optional[bytes] = None) -> bytes:
        if password is None:
            algorithm = serialization.NoEncryption()
        else:
            algorithm = serialization.BestAvailableEncryption(password)

        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=algorithm
        )

    def format_public_key(self) -> bytes:
        publick_key = self.key.public_key()
        return publick_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, msg: bytes) -> bytes:
        return self.key.sign(
            data=msg,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )

    @classmethod
    def generate(cls) -> 'RSAPrivateKey':
        # 参考 https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#generation
        # 在 2019.10.25 , 比较安全的 key_size 为 2048, 可能需要根据时间的不同修改此值.
        # public_exponent 不清楚干什么的, 官网推荐 65537.
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        return cls(key)

    @classmethod
    def load(cls, content: bytes, password: Optional[bytes] = None
             ) -> 'RSAPrivateKey':
        key = serialization.load_pem_private_key(
            data=content,
            password=password,
            backend=default_backend(),
        )
        return cls(key)


class RSAPublicKey:

    def __init__(self, key: '_RSAPublicKey'):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.key.encrypt(
            plaintext=plaintext,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def verify(self, signature, msg) -> bool:
        try:
            self.key.verify(
                signature=signature,
                data=msg,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                algorithm=hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    @classmethod
    def load(cls, content: bytes) -> 'RSAPublicKey':
        key = serialization.load_pem_public_key(
            data=content,
            backend=default_backend(),
        )
        return cls(key)


def fill_seq(seq: Seq, size: int, filler: Any) -> Seq:
    """用 `filler` 填充序列使其内被 `size` 整除.

    copy from https://github.com/dyq666/sanji
    """
    if not isinstance(seq, (str, bytes, list, tuple)):
        raise TypeError

    if len(seq) % size == 0:
        return seq

    num = size - (len(seq) % size)
    if isinstance(seq, (str, bytes)):
        return seq + filler * num
    else:  # list or tuple
        return seq + type(seq)(filler for _ in range(num))


def seq_grouper(seq: Seq, size: int, filler: Optional[Any] = None) -> Iterable:
    """按组迭代序列.

    `size`: 每组的大小.
    `filler`: 如果传入, 则用此值填充最后一组.

    copy from https://github.com/dyq666/sanji
    """
    if not isinstance(seq, (str, bytes, list, tuple)):
        raise TypeError

    if filler is not None:
        seq = fill_seq(seq, size, filler)
    times = math.ceil(len(seq) / size)
    return (seq[i * size: (i + 1) * size] for i in range(times))


def strip_seq(seq: Seq, size: int) -> Seq:
    """从末尾移除序列使其能被 `size` 整除.

    copy from https://github.com/dyq666/sanji
    """
    if not isinstance(seq, (str, bytes, list, tuple)):
        raise TypeError

    if len(seq) % size == 0:
        return seq

    num = len(seq) % size
    return seq[:-num]
