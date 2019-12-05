import pytest

from nami.symmetric import Feistel, OneTimePad
from nami.util import Binary


def test_oneTimePad():
    msg = '带带我'.encode()
    key = OneTimePad.generate_key(len(msg))
    pad = OneTimePad(key)
    assert pad.decrypt(pad.encrypt(msg)) == msg

    msg2 = '带带带我'.encode()
    key2 = OneTimePad.generate_key(len(msg2))
    pad2 = OneTimePad(key2)
    assert pad2.decrypt(pad2.encrypt(msg2)) == msg2
    with pytest.raises(ValueError):
        assert pad2.decrypt(pad2.encrypt(msg)) == msg


@pytest.mark.parametrize('algorithm', (
    lambda x, y: Binary.bytes_xor(x, y),
    lambda x, y: Binary.bytes_xor(10 * x, y),
))
@pytest.mark.parametrize('msg', (b'12', b'1234'))
@pytest.mark.parametrize('count', (9, 10))
def test_Feistel(algorithm, msg, count):
    key = Feistel.generate_key(len(msg) // 2)
    feistel = Feistel(key, count=count, algorithm=algorithm)

    ciphertext = feistel.encrypt(msg)
    res = feistel.decrypt(ciphertext)
    assert res == msg
