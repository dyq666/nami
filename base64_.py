"""
base64 编码解码核心过程 (不包含末尾补 '=' 的逻辑):

8

↓ 末尾补 '0' 使整个字符串可以被 6 整除
  a c -> 01100001 01100011 -> 01100001 01100011 00 -> 011000 010110 001100)

6

↓ 每个字节头部加两个 0, 按表转换
  011000 010110 001100 -> 00011000 00010110 00001100 -> Y W M

8

↓ 按表转换, 每个字节头部删去两个 0
  Y W M -> 00011000 00010110 00001100 -> 011000 010110 001100

6

↓ 删除用于补齐的 '0' (等价于让整个字符串可以被 8 整除)
  011000 010110 001100 -> 01100001 01100011 00 -> 01100001 01100011 ->  a c

8
"""

__all__ = (
    'b64decode',
    'b64encode',
)


from math import ceil
from string import ascii_uppercase, ascii_lowercase, digits
from typing import Optional, Generator

B64_CHARS = ascii_uppercase + ascii_lowercase + digits + '+/'
# 6 位二进制 -> char, 表中记录二进制比十进制在 base64 的编码解码过程中更加方便 (不是通过理论得出的, 仅从 Python 编写代码的角度上考虑)
B64_ENCODE_MAP = {format(i, '06b'): char for i, char in enumerate(B64_CHARS)}
B64_DECODE_MAP = {char: i for i, char in B64_ENCODE_MAP.items()}


def str_grouper(str_: str, n: int, default: Optional[str] = None) -> Generator:
    times = ceil(len(str_) / n)
    for i in range(times):
        item = str_[i * n: (i + 1) * n]
        if len(item) < n and default is not None:
            item += default * (n - len(item))
        yield item


def b64encode(s: bytes) -> bytes:
    # 二进制字符串
    bin_str = ''.join(format(b, '08b') for b in s)
    # 二进制字符串分组, 每组 6 个, 不足用 '0' 补齐
    six_group = (str_ for str_ in str_grouper(bin_str, 6, '0'))
    # 按 base64 表转换
    b64_chars = ''.join(B64_ENCODE_MAP[i] for i in six_group)
    # 用 '=' 将字符串补位四的倍数
    if len(b64_chars) % 4 != 0:
        b64_chars += '=' * (4 - len(b64_chars) % 4)
    return b64_chars.encode('ascii')


def b64decode(s: bytes) -> bytes:
    b64_chars = s.decode('ascii')
    b64_chars = b64_chars.rstrip('=')
    # 按 base64 表转换
    bin_str = ''.join(B64_DECODE_MAP[char] for char in b64_chars)
    # 二进制字符串分组, 每组 8 个, 余下部分删除 (余下的部分实际上编码过程中补充的 '0')
    if len(bin_str) % 8 != 0:
        bin_str = bin_str[:-(len(bin_str) % 8)]
    eight_group = (str_ for str_ in str_grouper(bin_str, 8))
    return bytes(int(i, 2) for i in eight_group)
