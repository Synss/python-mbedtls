import mbedtls._platform as _plt  # type: ignore


def test_platform() -> None:
    _plt.__self_test()
