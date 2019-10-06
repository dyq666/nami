import base64
import pytest

from util import b64encode


@pytest.mark.parametrize('string', (
    'A',
    'AB',
    'ABC',
    'ABCD',
    'dsadAb3CD231---k==.',
    '大赛的cvce1',
))
def test_base64(string):
    bytes_ = string.encode()
    assert b64encode(bytes_) == base64.b64encode(bytes_)