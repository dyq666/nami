__all__ = (
    'Binary',
    'fill_seq',
    'seq_grouper',
)

import math
from typing import Any, Iterable, Optional, Union

Seq = Union[str, bytes, list, tuple]


class Binary:
    """copy from https://github.com/dyq666/sanji """

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
        s1 = cls.bytes_2_str(b1)
        s2 = cls.bytes_2_str(b2)
        return cls.str_2_bytes(cls.str_xor(s1, s2))

    @classmethod
    def str_2_bytes(cls, s: str) -> bytes:
        """将 8 位二进制字符串转为字节."""
        if len(s) % 8 != 0:
            raise ValueError

        return bytes(int(item, 2) for item in seq_grouper(s, 8))

    @classmethod
    def bytes_2_str(cls, b: bytes) -> str:
        """将字节转为 8 位二进制字符串."""
        return ''.join(format(byte, '08b') for byte in b)


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
