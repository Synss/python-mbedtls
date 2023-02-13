# SPDX-License-Identifier: MIT

"""Unit tests for mbedtls.cipher."""

from __future__ import annotations

import pickle
import sys
from collections import defaultdict
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    NamedTuple,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import pytest

from mbedtls import has_feature
from mbedtls.cipher import (
    AES,
    ARC4,
    ARIA,
    CHACHA20,
    DES,
    DES3,
    AEADCipherType,
    Blowfish,
    Camellia,
    CipherType,
    DES3dbl,
    Mode,
    get_supported_ciphers,
)
from mbedtls.exceptions import TLSError


class Size(NamedTuple):
    key_size: Sequence[int]
    iv_size: int


T = TypeVar("T")


def constant(value: T) -> Callable[[], T]:
    return lambda: value


_CipherModule = TypeVar(
    "_CipherModule", bound=Union[CipherType, AEADCipherType]
)


SUPPORTED_SIZES: Mapping[object, Mapping[Mode, Size]] = {
    AES: defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.CCM: Size((16, 24, 32), 12),
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
            Mode.XTS: Size((32, 64), 16),
        },
    ),
    ARC4: defaultdict(
        constant(Size(key_size=(ARC4.key_size,), iv_size=0)),
        {Mode.CFB: Size((ARC4.key_size,), iv_size=ARC4.block_size)},
    ),
    ARIA: defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.CBC: Size((16, 24, 32), 16),
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
        },
    ),
    Blowfish: defaultdict(
        constant(Size(key_size=(16,), iv_size=8)),
        {Mode.ECB: Size((16,), 0)},
    ),
    Camellia: defaultdict(
        constant(Size(key_size=(16, 24, 32), iv_size=16)),
        {
            Mode.ECB: Size((16, 24, 32), 0),
            Mode.GCM: Size((16, 24, 32), 12),
        },
    ),
    CHACHA20: defaultdict(
        constant(Size(key_size=(CHACHA20.key_size,), iv_size=12)),
        {Mode.ECB: Size((CHACHA20.key_size,), 0)},
    ),
    DES: defaultdict(
        constant(Size(key_size=(DES.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES.key_size,), 0)},
    ),
    DES3: defaultdict(
        constant(Size(key_size=(DES3.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES3.key_size,), 0)},
    ),
    DES3dbl: defaultdict(
        constant(Size(key_size=(DES3dbl.key_size,), iv_size=8)),
        {Mode.ECB: Size((DES3dbl.key_size,), 0)},
    ),
}


SUPPORTED_MODES: Mapping[object, Sequence[Mode]] = {
    AES: (
        Mode.ECB,
        Mode.CBC,
        Mode.CFB,
        Mode.CTR,
        Mode.OFB,
        Mode.XTS,
    ),
    ARC4: (Mode.STREAM,),
    ARIA: (Mode.ECB, Mode.CBC, Mode.CTR, Mode.GCM),
    Blowfish: (Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR),
    Camellia: (
        Mode.ECB,
        Mode.CBC,
        Mode.CFB,
        Mode.CTR,
        Mode.GCM,
    ),
    CHACHA20: (Mode.STREAM,),
    DES: (Mode.ECB, Mode.CBC),
    DES3: (Mode.ECB, Mode.CBC),
    DES3dbl: (Mode.ECB, Mode.CBC),
}

SUPPORTED_CIPHERS: Sequence[object] = tuple(SUPPORTED_MODES.keys())

SUPPORTED_AEAD_MODES: Mapping[object, Sequence[Mode]] = {
    AES: (Mode.GCM, Mode.CCM),
    CHACHA20: (Mode.CHACHAPOLY,),
}

SUPPORTED_AEAD_CIPHERS: Sequence[object] = tuple(SUPPORTED_AEAD_MODES)


def modname(mod: _CipherModule) -> str:
    return mod.__name__.rsplit(".", 1)[-1]


def gen_cipher_data(
    module: object,
    *,
    modes: Mapping[object, Sequence[Mode]],
) -> Iterator[Tuple[int, Mode, int]]:
    for mode in modes[module]:
        sizes = SUPPORTED_SIZES[module][mode]
        for key_size in sizes.key_size:
            yield key_size, mode, sizes.iv_size


def gen_cipher(
    modules: Iterable[object],
    *,
    modes: Mapping[object, Sequence[Mode]],
) -> Iterator[Tuple[object, int, Mode, int]]:
    for module in modules:
        for key_size, mode, iv_size in gen_cipher_data(module, modes=modes):
            yield module, key_size, mode, iv_size


def paramids(params: Tuple[_CipherModule, int, Mode, int]) -> str:
    module, key_size, mode, iv_size = params
    return (
        f"{module.__name__}, "
        f"key_size={key_size}, "
        f"mode={mode!s}, "
        f"iv_size={iv_size}"
    )


def test_get_supported_ciphers() -> None:
    # Check a few basic ciphers that really have to be present.
    assert b"AES-128-ECB" in get_supported_ciphers()
    assert b"AES-192-ECB" in get_supported_ciphers()
    assert b"AES-256-ECB" in get_supported_ciphers()


class TestCipher:
    @pytest.fixture(
        params=gen_cipher(SUPPORTED_CIPHERS, modes=SUPPORTED_MODES),
        ids=paramids,
    )
    def params(self, request: Any) -> Tuple[CipherType, int, Mode, int]:
        module: CipherType = request.param[0]
        name = modname(module)
        if not has_feature({"DES3": "DES", "DES3dbl": "DES"}.get(name, name)):
            return pytest.skip(f"{name} unavailable")
        assert isinstance(ARIA, CipherType)
        if module is ARIA and sys.platform.startswith("win"):
            return pytest.skip("unsupported")

        return cast(Tuple[CipherType, int, Mode, int], request.param)

    def test_pickle(
        self,
        params: Tuple[CipherType, int, Mode, int],
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
        cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(cipher)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(
        self,
        params: Tuple[CipherType, int, Mode, int],
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
        cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
        assert cipher.key_size == key_size
        assert cipher.mode == mode
        assert cipher.iv_size == iv_size
        assert module.block_size == cipher.block_size
        assert module.key_size in {module.key_size, None}

    def test_cipher_name(
        self,
        params: Tuple[CipherType, int, Mode, int],
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
        cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
        assert str(cipher) == cipher.name.decode("ascii")

    def test_encrypt_decrypt(
        self,
        params: Tuple[CipherType, int, Mode, int],
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
        cipher = module.new(randbytes(key_size), mode, randbytes(iv_size))
        data = randbytes(
            cipher.block_size
            if cipher.mode is Mode.ECB
            else cipher.block_size * 128
        )
        assert cipher.decrypt(cipher.encrypt(data)) == data


class TestAEADCipher:
    @pytest.fixture(
        params=gen_cipher(SUPPORTED_AEAD_CIPHERS, modes=SUPPORTED_AEAD_MODES),
        ids=paramids,
    )
    def params(self, request: Any) -> Tuple[AEADCipherType, int, Mode, int]:
        module: AEADCipherType = request.param[0]
        name = modname(module)
        if not has_feature({"DES3": "DES", "DES3dbl": "DES"}.get(name, name)):
            return pytest.skip(f"{name} unavailable")

        return cast(Tuple[AEADCipherType, int, Mode, int], request.param)

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_pickle(
        self,
        params: Tuple[AEADCipherType, int, Mode, int],
        ad_size: int,
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
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
    def test_accessors(
        self,
        params: Tuple[AEADCipherType, int, Mode, int],
        ad_size: int,
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
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
    def test_cipher_name(
        self,
        params: Tuple[AEADCipherType, int, Mode, int],
        ad_size: int,
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
        cipher = module.new(
            randbytes(key_size),
            mode,
            iv=randbytes(iv_size),
            ad=randbytes(ad_size),
        )
        assert str(cipher) == cipher.name.decode("ascii")

    @pytest.mark.parametrize("ad_size", [0, 1, 16, 256])
    def test_encrypt_decrypt(
        self,
        params: Tuple[AEADCipherType, int, Mode, int],
        ad_size: int,
        randbytes: Callable[[int], bytes],
    ) -> None:
        module, key_size, mode, iv_size = params
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


class TestVector:
    def test_aes_128_gcm(self) -> None:
        key = bytes.fromhex(32 * "0")
        nonce = bytes.fromhex(24 * "0")
        plaintext = b""
        ciphertext = b""
        adata = b""
        mac = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")

        cipher = AES.new(key, Mode.GCM, nonce, adata)
        assert cipher.encrypt(plaintext) == (ciphertext, mac)
        assert cipher.decrypt(*cipher.encrypt(plaintext)) == plaintext

    def test_aes_256_gcm(self) -> None:
        key = bytes.fromhex(64 * "0")
        nonce = bytes.fromhex(24 * "0")
        plaintext = b""
        ciphertext = b""
        adata = b""
        mac = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

        cipher = AES.new(key, Mode.GCM, nonce, adata)
        assert cipher.encrypt(plaintext) == (ciphertext, mac)
        assert cipher.decrypt(*cipher.encrypt(plaintext)) == plaintext


class TestGenericCipher:
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
    def module(self, request: Any) -> CipherType:
        module: CipherType = request.param
        name = modname(module)
        if not has_feature({"DES3": "DES", "DES3dbl": "DES"}.get(name, name)):
            return pytest.skip(f"{name} unavailable")
        assert isinstance(ARIA, CipherType)
        if module is ARIA and sys.platform.startswith("win"):
            return pytest.skip("unsupported")
        return module

    def test_unsupported_mode(
        self, module: CipherType, randbytes: Callable[[int], bytes]
    ) -> None:
        supported_modes = frozenset(SUPPORTED_MODES[module]) | frozenset(
            SUPPORTED_AEAD_MODES.get(module, ())
        )
        for key_size, mode, iv_size in gen_cipher_data(
            module,
            modes={module: tuple(frozenset(Mode) - supported_modes)},
        ):
            with pytest.raises(TLSError) as excinfo:
                module.new(randbytes(key_size), mode, randbytes(iv_size))

            assert excinfo.value.msg.startswith("unsupported mode")

    def test_cbc_requires_padding(
        self, module: CipherType, randbytes: Callable[[int], bytes]
    ) -> None:
        mode = Mode.CBC
        if mode not in SUPPORTED_MODES[module]:
            pytest.skip(f"unsupported mode for {module!r}: {mode!s}")

        sizes = SUPPORTED_SIZES[module][mode]
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
