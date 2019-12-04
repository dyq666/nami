import pytest

from nami.symmetric import Feistel, OneTimePad


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


def test_Feistel():
    feistel = Feistel(10)
    plaintext = 'ab'.encode()

    ciphertext = feistel.encrypt(plaintext)
    assert feistel.decrypt(ciphertext) == plaintext
