"""Unit tests for mbedtls.cipher."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name, redefined-outer-name

import pickle
import sys
from collections import defaultdict
from typing import (
    Callable,
    Iterator,
    Mapping,
    NamedTuple,
    Sequence,
    Tuple,
    TypeVar,
)

import pytest  # type: ignore

from mbedtls.cipher import (  # type: ignore
    AES,
    ARC4,
    ARIA,
    CHACHA20,
    DES,
    DES3,
    MODE_CBC,
    MODE_CFB,
    Blowfish,
    Camellia,
    Cipher,
    DES3dbl,
    Mode,
    get_supported_ciphers,
)
from mbedtls.cipher._cipher import CIPHER_NAME  # type: ignore
from mbedtls.exceptions import TLSError  # type: ignore


class Size(NamedTuple):
    key_size: Sequence[int]
    iv_size: int


T = TypeVar("T")


def constant(value: T) -> Callable[[], T]:
    return lambda: value


SUPPORTED_SIZES: Mapping[str, Mapping[Mode, Size]] = {
    "mbedtls.cipher.AES": defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.CCM: Size((16, 24, 32), 12),
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
            Mode.XTS: Size((32, 64), 16),
        },
    ),
    "mbedtls.cipher.ARC4": defaultdict(
        constant(Size(key_size=(ARC4.key_size,), iv_size=0)),
        {Mode.CFB: Size((ARC4.key_size,), iv_size=ARC4.block_size)},
    ),
    "mbedtls.cipher.ARIA": defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.CBC: Size((16, 24, 32), 16),
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
        },
    ),
    "mbedtls.cipher.Blowfish": defaultdict(
        constant(Size(key_size=(16,), iv_size=8)),
        {Mode.ECB: Size((16,), 0)},
    ),
    "mbedtls.cipher.Camellia": defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
        },
    ),
    "mbedtls.cipher.CHACHA20": defaultdict(
        constant(Size(key_size=(CHACHA20.key_size,), iv_size=12)),
        {Mode.ECB: Size((CHACHA20.key_size,), 0)},
    ),
    "mbedtls.cipher.DES": defaultdict(
        constant(Size(key_size=(DES.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES.key_size,), 0)},
    ),
    "mbedtls.cipher.DES3": defaultdict(
        constant(Size(key_size=(DES3.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES3.key_size,), 0)},
    ),
    "mbedtls.cipher.DES3dbl": defaultdict(
        constant(Size(key_size=(DES3dbl.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES3dbl.key_size,), 0)},
    ),
}


SUPPORTED_MODES: Mapping[str, Sequence[Mode]] = {
    "mbedtls.cipher.AES": (
        Mode.ECB,
        Mode.CBC,
        Mode.CFB,
        Mode.CTR,
        Mode.OFB,
        Mode.XTS,
    ),
    "mbedtls.cipher.ARC4": (Mode.STREAM,),
    "mbedtls.cipher.ARIA": (Mode.ECB, Mode.CBC, Mode.CTR, Mode.GCM),
    "mbedtls.cipher.Blowfish": (Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR),
    "mbedtls.cipher.Camellia": (
        Mode.ECB,
        Mode.CBC,
        Mode.CFB,
        Mode.CTR,
        Mode.GCM,
    ),
    "mbedtls.cipher.CHACHA20": (Mode.STREAM,),
    "mbedtls.cipher.DES": (Mode.ECB, Mode.CBC),
    "mbedtls.cipher.DES3": (Mode.ECB, Mode.CBC),
    "mbedtls.cipher.DES3dbl": (Mode.ECB, Mode.CBC),
}


SUPPORTED_AEAD_MODES: Mapping[str, Sequence[Mode]] = {
    "mbedtls.cipher.AES": (Mode.GCM, Mode.CCM),
    "mbedtls.cipher.CHACHA20": (Mode.CHACHAPOLY,),
}


def gen_cipher_data(
    module: type, *, modes: Mapping[str, Sequence[Mode]]
) -> Iterator[Tuple[int, Mode, int]]:
    for mode in modes[module.__name__]:
        sizes = SUPPORTED_SIZES[module.__name__][mode]
        for key_size in sizes.key_size:
            yield key_size, mode, sizes.iv_size


def test_cipher_list() -> None:
    assert len(CIPHER_NAME) == 74


def test_get_supported_ciphers() -> None:
    cl = get_supported_ciphers()
    assert cl and set(cl).issubset(set(CIPHER_NAME))


def test_wrong_size_raises_exception() -> None:
    with pytest.raises(NotImplementedError):
        Cipher(b"AES-512-ECB", b"", Mode.ECB, b"")


def test_random_name_raises_exception() -> None:
    with pytest.raises(NotImplementedError):
        Cipher(b"RANDOM TEXT IS NOT A CIPHER", b"", Mode.ECB, b"")


def test_zero_length_raises_exception() -> None:
    with pytest.raises(NotImplementedError):
        Cipher(b"", b"", Mode.ECB, b"")


@pytest.mark.parametrize("mode", [MODE_CBC, Mode.CBC])
def test_cbc_raises_value_error_without_iv(mode: Mode) -> None:
    with pytest.raises(ValueError):
        Cipher(b"AES-512-CBC", b"", mode, b"")


@pytest.mark.parametrize("mode", [MODE_CFB, Mode.CFB])
def test_cfb_raises_value_error_without_iv(mode: Mode) -> None:
    with pytest.raises(ValueError):
        Cipher(b"AES-512-CFB", b"", mode, b"")


class TestCipher:
    @pytest.fixture(
        params=[
            AES,
            ARC4,
            ARIA,
            Blowfish,
            Camellia,
            CHACHA20,
            DES,
            DES3,
            DES3dbl,
        ]
    )
    def module(self, request):
        if request.param is ARIA and sys.platform.startswith("win"):
            return pytest.skip()
        return request.param

    def test_pickle(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            with pytest.raises(TypeError) as excinfo:
                pickle.dumps(cipher)

            assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            assert cipher.key_size == key_size
            assert cipher.mode == mode
            assert cipher.iv_size == iv_size
            assert module.block_size == cipher.block_size
            assert module.key_size in {module.key_size, None}

    def test_cipher_name(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            assert cipher.name in CIPHER_NAME
            assert CIPHER_NAME[cipher._type] == cipher.name
            assert str(cipher) == cipher.name.decode("ascii")

    def test_unsupported_mode(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module,
            modes={
                module.__name__: tuple(
                    frozenset(Mode)
                    - (
                        set(SUPPORTED_MODES[module.__name__])
                        | set(SUPPORTED_AEAD_MODES.get(module.__name__, set()))
                    )
                )
            },
        ):
            with pytest.raises(TLSError) as excinfo:
                module.new(randbytes(key_size), mode, randbytes(iv_size))

            assert excinfo.value.msg.startswith("unsupported mode")

    def test_encrypt_decrypt(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            data = randbytes(
                cipher.block_size
                if cipher.mode is Mode.ECB
                else cipher.block_size * 128
            )
            assert cipher.decrypt(cipher.encrypt(data)) == data

    def test_encrypt_nothing_raises(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            with pytest.raises(TLSError):
                cipher.encrypt(b"")

    def test_decrypt_nothing_raises(self, module, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_MODES
        ):
            cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
            with pytest.raises(TLSError):
                cipher.decrypt(b"")

    def test_cbc_requires_padding(self, module, randbytes):
        mode = Mode.CBC
        if mode not in SUPPORTED_MODES[module.__name__]:
            return pytest.skip(
                f"unsupported mode for {module.__name__!r}: {mode!s}"
            )

        sizes = SUPPORTED_SIZES[module.__name__][mode]
        for key_size in sizes.key_size:
            cipher = module.new(
                randbytes(key_size), mode, iv=randbytes(sizes.iv_size)
            )
            data = randbytes(
                cipher.block_size
                if cipher.mode is Mode.ECB
                else cipher.block_size * 128
            )
            data += b"\0"
            if cipher.mode is Mode.CBC:
                with pytest.raises(ValueError):
                    cipher.encrypt(data)


class TestAEADCipher:
    @pytest.fixture(params=[AES, CHACHA20])
    def module(self, request):
        return request.param

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_pickle(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            with pytest.raises(TypeError) as excinfo:
                pickle.dumps(cipher)

            assert str(excinfo.value).startswith("cannot pickle")

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_accessors(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            assert cipher.key_size == key_size
            assert cipher.mode == mode
            assert cipher.iv_size == iv_size
            assert module.block_size == cipher.block_size
            assert module.key_size in {module.key_size, None}

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_cipher_name(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            assert cipher.name in CIPHER_NAME
            assert CIPHER_NAME[cipher._type] == cipher.name
            assert str(cipher) == cipher.name.decode("ascii")

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_encrypt_decrypt(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            data = randbytes(
                cipher.block_size
                if cipher.mode is Mode.ECB
                else cipher.block_size * 128
            )
            msg, tag = cipher.encrypt(data)
            assert cipher.decrypt(msg, tag) == data

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_encrypt_nothing_raises(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            with pytest.raises(TLSError):
                cipher.encrypt(b"")

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_decrypt_nothing_raises(self, module, ad_size, randbytes):
        for key_size, mode, iv_size in gen_cipher_data(
            module, modes=SUPPORTED_AEAD_MODES
        ):
            cipher = module.new(
                randbytes(key_size),
                mode,
                iv=randbytes(iv_size),
                ad=randbytes(ad_size),
            )
            data = randbytes(
                cipher.block_size
                if cipher.mode is Mode.ECB
                else cipher.block_size * 128
            )
            msg, tag = cipher.encrypt(data)
            with pytest.raises(TLSError):
                cipher.decrypt(b"", tag)
