import base64
import pytest

from base64_ import b64decode, b64encode


"""test for base64_.py"""


@pytest.mark.parametrize('str_', (
    'A',
    'AB',
    'ABC',
    'ABCD',
    'ABCDE',
    'ABCDEF',
    'ABCDEFG',
    'ABCDEFGH',
    'dsadAb3CD231---k==.',
    '大赛的cvce1',
))
def test_base64(str_):
    bytes_ = str_.encode()
    assert b64encode(bytes_) == base64.b64encode(bytes_)

    b64 = base64.b64encode(bytes_)
    assert b64decode(b64) == base64.b64decode(b64)
