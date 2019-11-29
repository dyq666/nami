from util import RSAPrivateKey, RSAPublicKey


def test_rsa_signature():
    private_key = RSAPrivateKey.generate()
    public_key = RSAPublicKey.load(private_key.format_public_key())
    msg = b'1'
    signature = private_key.sign(msg)

    assert public_key.verify(signature, msg)
    assert not public_key.verify(signature, msg + b'2')
