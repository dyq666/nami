__all__ = (
    'b64encode',
)

from itertools import zip_longest
from string import ascii_uppercase, ascii_lowercase, digits
from typing import Iterable, Optional, Any

B64_VARS = ascii_uppercase + ascii_lowercase + digits + '+/='
B64_MAP = {i: char for i, char in enumerate(B64_VARS)}


def grouper(iterable: Iterable, n: int,
            fillvalue: Optional[Any] = None) -> Iterable:
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def b64encode(s: bytes) -> bytes:
    """步骤
    1. 将每个 byte 转成二进制字符串, 再 join
    2. 将二进制字符串按 6 个分组, 最后一组如果不够 6 个, 用 '0' 补齐
    3. 将个二进制字符串转为十进制在根据 b64 表转成字符, 再 join
    4. 如果 join 后的字符串不是四的倍数, 则用 '=' 补齐
    """
    bin_str = ''.join(format(b, '08b') for b in s)
    six_group = (''.join(i) for i in grouper(bin_str, 6, '0'))
    b64_chars = ''.join(B64_MAP[int(i, 2)] for i in six_group)
    _mod = len(b64_chars) % 4
    b64_chars += '=' * (4 - _mod if _mod != 0 else 0)
    return b64_chars.encode('ascii')
