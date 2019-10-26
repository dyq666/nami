"""公钥密码

1. 公钥加密, 私钥解密.

私钥存放在接收者. 公钥由接收者配送给发送者.
其他人拿不到私钥就无法解密, 因此公钥配送过程中不用担心被窃取.

2. mod 运算



"""

from typing import TYPE_CHECKING, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey


class Mod12:

    """mod 12 的世界只有 0 - 11"""

    def __init__(self, value: int):
        if value >= 12:
            raise ValueError
        self.v = value

    def __repr__(self):
        return (
            f'<{self.__class__.__name__}'
            f' v={self.v!r}'
            f'>'
        )

    def __eq__(self, other: 'Mod12'):
        return all((
            type(self) == type(other),
            self.v == other.v
        ))

    def __add__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v + other.v) % 12
        return type(self)(value)

    def __sub__(self, other: 'Mod12') -> 'Mod12':
        """
        1. y + y' = 0
        2. x - y = x + y'

        根据上面的式子我们可以将减法转换成加法.

        枚举 y 等于 [0, 11] 找到符合式子 1 中的 y' 值
        可以发现: 除了 0 的 y' 是 0 以外其他 y' = 12 - y
        具体可以看 `Mod12.search_sub`
        """
        value = 0 if other.v == 0 else (12 - other.v)
        return self + type(self)(value)

    def __mul__(self, other: 'Mod12') -> 'Mod12':
        value = (self.v * other.v) % 12
        return type(self)(value)

    def __truediv__(self, other: 'Mod12') -> Optional['Mod12']:
        """
        根据 Mod12.search_truediv 的结果来看, 只有 1, 5, 7, 11 可以将除法转乘法
        """
        if other.v not in {1, 5, 7, 11}:
            return
        return self * other

    @classmethod
    def search_sub(cls):
        for i in range(12):
            for j in range(12):
                x = cls(i)
                y = cls(j)
                res = x + y
                if res.v == 0:
                    print(f'{x.v:2d} + {y.v:2d} = {res.v}')

    @classmethod
    def search_truediv(cls):
        for i in range(12):
            for j in range(12):
                x = cls(i)
                y = cls(j)
                res = x * y
                if res.v == 1:
                    print(f'{x.v:2d} + {y.v:2d} = {res.v}')


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

    @classmethod
    def load(cls, content: bytes) -> 'RSAPublicKey':
        key = serialization.load_pem_public_key(
            data=content,
            backend=default_backend(),
        )
        return cls(key)
