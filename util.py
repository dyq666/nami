__all__ = (
    'fill_sequence',
    'sequence_grouper',
)

import math
from typing import Any, Iterable, Optional, Sequence


def fill_sequence(sequence: Sequence, size: int, filler: Any) -> Sequence:
    """copy from https://github.com/dyq666/util"""
    if not isinstance(sequence, (str, bytes, list, tuple)):
        raise TypeError
    if len(sequence) % size == 0:
        return sequence

    filler_number = size - (len(sequence) % size)
    if isinstance(sequence, (str, bytes)):
        return sequence + filler * filler_number
    elif isinstance(sequence, (list, tuple)):
        return sequence + type(sequence)(filler for _ in range(filler_number))


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
