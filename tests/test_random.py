"""Unit tests for mbedtls.random."""


import mbedtls.random as rnd


def test_instantiation():
    rnd.Random()
