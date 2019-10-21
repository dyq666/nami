"""
## 个人理解

base64 最初用于解决邮件无法识别非 ascii 的字节 (7 bit). 具体方式是增加数据冗余, 将 8 bit
的表示形式转换成 6 bit + 填充 0 的方式, 当然转换更少 bit 的算法, 转化的位数越低, 数据相较之前的数据
就越大. 从这个角度上看可能 base128 更优秀, 但 ascii 中有一部分控制字符, 控制字符不易读, 因此
最常用的还是 base64. base64 中选取了 64 个可读的字符, 这里比较可惜的是, 大小字母 + 数组只有 62 个,
因此又选了 `+/` 这两个字符, 这个选择也导致了一些问题. 如果 `+/` 在一些数据中是类似 `关键字` 的存在,
那么就不能直接使用标准的 base64, 例如 url.

现在仍广泛应用 base64 的原因可能是 base64 的转换表, 这张转换表具有简单的加密和编码后数据易读的功能.

为什么要末尾加 `=` 呢 ?
https://stackoverflow.com/questions/4080988/why-does-base64-encoding-require-padding-if-the-input-length-is-not-divisible-by

## base64 编码解码核心过程 (不包含末尾补 '=' 的逻辑):

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


from string import ascii_uppercase, ascii_lowercase, digits

from util import fill_str, sequence_grouper

B64_CHARS = ascii_uppercase + ascii_lowercase + digits + '+/'
# 6 位二进制 -> char, 表中记录二进制比十进制在 base64 的编码解码过程中更加方便 (不是通过理论得出的, 仅从 Python 编写代码的角度上考虑)
B64_ENCODE_MAP = {format(i, '06b'): char for i, char in enumerate(B64_CHARS)}
B64_DECODE_MAP = {char: i for i, char in B64_ENCODE_MAP.items()}


def b64encode(s: bytes) -> bytes:
    # 二进制字符串
    bin_str = ''.join(format(b, '08b') for b in s)
    # 二进制字符串分组, 每组 6 个, 不足用 '0' 补齐
    six_group = (str_ for str_ in sequence_grouper(bin_str, 6, '0'))
    # 按 base64 表转换
    b64_chars = ''.join(B64_ENCODE_MAP[i] for i in six_group)
    b64_chars = fill_str(b64_chars, 4, '=')
    return b64_chars.encode('ascii')


def b64decode(s: bytes) -> bytes:
    b64_chars = s.decode('ascii')
    b64_chars = b64_chars.rstrip('=')
    # 按 base64 表转换
    bin_str = ''.join(B64_DECODE_MAP[char] for char in b64_chars)
    # 二进制字符串分组, 每组 8 个, 余下部分删除 (余下的部分实际上编码过程中补充的 '0')
    if len(bin_str) % 8 != 0:
        bin_str = bin_str[:-(len(bin_str) % 8)]
    eight_group = (str_ for str_ in sequence_grouper(bin_str, 8))
    return bytes(int(i, 2) for i in eight_group)
