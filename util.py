__all__ = (
    'fill_str',
    'sequence_grouper',
)

import math
from typing import Any, Iterable, Optional, Sequence


def fill_str(str_: str, number: int, filler: str) -> str:
    """copy from https://github.com/dyq666/util"""
    if len(str_) % number == 0:
        return str_

    return str_ + filler * (number - len(str_) % number)


def sequence_grouper(sequence: Sequence, size: int,
                     default: Optional[Any] = None) -> Iterable:
    """copy from https://github.com/dyq666/util"""
    if not isinstance(sequence, (str, bytes, list, tuple)):
        print(sequence, type(sequence))
        raise TypeError

    times = math.ceil(len(sequence) / size)
    for i in range(times):
        item = sequence[i * size: (i + 1) * size]
        if default is not None:
            missing_number = size - len(item)
            if isinstance(sequence, (str, bytes)):
                item += default * missing_number
            elif isinstance(sequence, (list, tuple)):
                item += type(sequence)(default for _ in range(missing_number))
            yield item
        else:
            yield item
