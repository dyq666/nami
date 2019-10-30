"""消息认证码 MAC -> Message Authentication Code

## 基本功能

场景:

```
       从 A 账户向 B 账户汇款 1000 元
Alice             ->                Bob
```

在场景中 Bob 收到消息后需要确认两件事:

1. 消息是否被篡改. (完整性)

2. 消息是不是 Alice 发的. (认证)

使用消息认证码可以同时确认上述两件事.

## 构成

输入: 任意长度的消息, 密钥

输出: 固定长度的数据, 这个数据称为 MAC 值

MAC 虽然有多种实现方式, 但通常由 `与密钥相关联的单向散列函数` 实现. 其中
单向散列函数负责完整性验证, 密钥负责认证. 例如: HMAC

## 使用步骤

```
Alice 和 Bob 共享密钥.

       1. 从 A 账户向 B 账户汇款 1000 元
       2. 使用 `与密钥相关联的单向散列函数` 计算出消息的 mac 值
Alice             ->                Bob

Bob 使用 `与密钥相关联的单向散列函数` 计算出拿到的消息的 mac 值,
然后和拿到的 mac 值对比, 如果相同则通过了完整性和认证.
```
"""

__all__ = (
    'HMAC',
)

import hmac
from hashlib import sha256


class HMAC:

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        h = hmac.new(self.key, plaintext, sha256)
        return h.hexdigest()
