import mbedtls._platform as _plt  # type: ignore


def test_platform():
    _plt.__self_test()
