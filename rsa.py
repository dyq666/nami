"""公钥密码

1. 公钥加密, 私钥解密.

私钥存放在接收者. 公钥由接收者配送给发送者.
其他人拿不到私钥就无法解密, 因此公钥配送过程中不用担心被窃取.

"""

from typing import TYPE_CHECKING, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey


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
