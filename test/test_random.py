import pytest

from nami.random_ import HashRandom, LinearCongruentialRandom


@pytest.mark.parametrize('random_gen', (
    HashRandom(), LinearCongruentialRandom(3, 0, 7)
))
def test_crypto_random(random_gen):
    random_gen.seed(1)
    v1 = random_gen.random()
    v2 = random_gen.random()
    random_gen.seed(1)
    v3 = random_gen.random()
    assert v1 != v2
    assert v1 == v3
