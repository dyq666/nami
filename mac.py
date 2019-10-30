"""消息认证码 MAC -> Message Authentication Code

## 基本功能

场景:

```
       从 A 账户向 B 账户汇款 1000 元
Alice             ->                Bob
```

在场景中 Bob 收到消息后需要确认两件事:

1. 消息是否被篡改. (完整性)

2. 消息是不是 Alice 写的. (认证)

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

## 抵御重放攻击 (repeat attack)

在 `使用步骤章节` Alice 向 Bob 发送信息的过程中, 窃取者可以获取到消息和 mac.
窃取者虽然不能篡改消息以及仿造消息了, 但可以向 Bob 重复发送劫获的消息和 mac, 这样 Bob 可能会执行
多次汇款操作, 对于窃取者来说这是一个损人不利己的事情.

要防御重放攻击就需要 Bob 确认发送者是 Alice.

书上说的解决办法是提供一个随机数 nonce.

Alice 发送消息前先向 Bob 获取一个随机数 nonce, 发送数据时带上 nonce,
Bob 验证 nonce 确认是 Alice 发的.

但是这种方法又引入了一些麻烦的事情, 比如先要安全的配送 nonce, 以及 Bob 得存储 nonce.

TODO 因此可能需要一种更易用的方式, 具体还没查到...
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
