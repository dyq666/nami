from nami.symmetric import Feistel, OneTimePad


def test_oneTimePad():
    plaintext = '带带我'.encode()
    ciphertext, key = OneTimePad.encrypt(plaintext)
    assert OneTimePad.decrypt(ciphertext, key) == plaintext


def test_Feistel():
    feistel = Feistel(10)
    plaintext = 'ab'.encode()

    ciphertext = feistel.encrypt(plaintext)
    assert feistel.decrypt(ciphertext) == plaintext
