from nami.hash_func import BirthdayParadox


def test_birthday_paradox():
    assert BirthdayParadox.least_number_365(p=0.5) == 23
    assert f'{BirthdayParadox.probability_365(n=23):.1f}' == '0.5'
