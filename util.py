__all__ = (
    'b64encode',
)

import math
from string import ascii_uppercase, ascii_lowercase, digits

B64_VARS = ascii_uppercase + ascii_lowercase + digits + '+/='
B64_MAP = {i: char for i, char in enumerate(B64_VARS)}


def _bin(number: int) -> str:
    """将字符转换成 8 位的二进制字符串"""
    binary = bin(number).lstrip('0b')
    return '0' * (8 - len(binary)) + binary


def b64encode(r1: bytes) -> bytes:
    """步骤
    1. bytes 转换成二进制字符串, 在合并
    2. 合并后的字符串按 6 分组, 不够 6 的用 0 补齐
    3. 按 6 分组后的每项在前头补 2 个 0
    4. 每项再从二进制转化为十进制
    5. 根据字符表映射码转换为字符
    6. 转化后的字符组不够 4 的倍数, 需要用 '=' 补齐
    """
    r1 = ''.join(_bin(b) for b in r1)
    r2 = [r1[i * 6: (i + 1) * 6] for i in range(math.ceil(len(r1) / 6))]
    r2[-1] += '0' * (6 - len(r2[-1]))
    r3 = (f'00{i}' for i in r2)
    r4 = (int(i, 2) for i in r3)
    r5 = [B64_MAP[i] for i in r4]
    r6 = r5 + (['=' for _ in range(4 - len(r5) % 4)] if len(r5) % 4 != 0 else [])
    return ''.join(r6).encode('ascii')
