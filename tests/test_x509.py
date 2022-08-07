# SPDX-License-Identifier: MIT

from __future__ import annotations

import datetime as dt
import pickle
import sys
from typing import Any, Callable, Optional, Tuple, Union

import certifi
import pytest

from mbedtls import hashlib
from mbedtls.pk import ECC, RSA
from mbedtls.x509 import CRL, CRT, CSR, BasicConstraints

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final

_PEM = str
_DER = bytes
_PKey = Union[ECC, RSA]

CRL_PEM: Final[
    _PEM
] = """
-----BEGIN X509 CRL-----
MIIBqzCBlDANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDERMA8GA1UEChMI
UG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EXDTExMDIyMDEwMjI1
OVoXDTE5MTEyNTEwMjI1OVowKDASAgEBFw0xMTAyMTIxNDQ0MDdaMBICAQMXDTEx
MDIxMjE0NDQwN1owDQYJKoZIhvcNAQEFBQADggEBAJYuWdKPdblMVWCnxpMnchuL
dqWzK2BA0RelCaGjpxuwX3NmLDm+5hKja/DJxaRqTOf4RSC3kcX8CdIldsLO96dz
//wAQdFPDhy6AFT5vKTO8ItPHDb7qFOqFqpeJi5XN1yoZGTB1ei0mgD3xBaKbp6U
yCOZJSIFomt7piT4GcgWVHLUmpyHDDeodNhYPrN0jf2mr+ECd9fQJYdz1qm0Xx+Q
NbKXDiPRmPX0qVleCZSeSp1JAmU4GoCO+96qQUpjgll+6xWya3UNj61f9sh0Zzr7
5ug2LZo5uBM/LpNR1K3TLxNCcg7uUPTn9r143d7ivJhPl3tEJn4PXjv6mlLoOgU=
-----END X509 CRL-----
"""
# This CRL is from mbed TLS: `tests/data_files/crl.pem`.


@pytest.fixture(scope="module")
def now() -> dt.datetime:
    return dt.datetime.utcnow().replace(microsecond=0)


def make_csr(
    key: Optional[_PKey] = None,
    subject: Optional[str] = None,
    digestmod: Optional[hashlib.Algorithm] = None,
) -> Tuple[CSR, _PKey]:
    if key is None:
        key = RSA()
        key.generate()
    if subject is None:
        subject = "OU=test, CN=example.com"
    if digestmod is None:
        digestmod = hashlib.sha256
    return CSR.new(key, subject, digestmod()), key


def make_root_ca(
    subject: Optional[str] = None,
    not_before: Optional[dt.datetime] = None,
    not_after: Optional[dt.datetime] = None,
    serial_number: Optional[int] = None,
    basic_constraints: Optional[BasicConstraints] = None,
    digestmod: Optional[hashlib.Algorithm] = None,
    csr_key_pair: Optional[Tuple[CSR, _PKey]] = None,
) -> Tuple[CRT, _PKey]:
    if subject is None:
        subject = "OU=test, CN=Trusted CA"
    if not_before is None:
        not_before = dt.datetime.utcnow()
    if not_after is None:
        not_after = not_before + dt.timedelta(days=90)
    if serial_number is None:
        serial_number = 0x123456
    if basic_constraints is None:
        basic_constraints = BasicConstraints(True, -1)
    if digestmod is None:
        digestmod = hashlib.sha256
    if csr_key_pair is None:
        csr, key = make_csr(subject=subject, digestmod=digestmod)
    else:
        csr, key = csr_key_pair

    return (
        CRT.selfsign(
            csr=csr,
            issuer_key=key,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_number,
            basic_constraints=basic_constraints,
        ),
        key,
    )


def make_crt(
    issuer_crt: CRT,
    issuer_key: _PKey,
    subject: Optional[str] = None,
    not_before: Optional[dt.datetime] = None,
    not_after: Optional[dt.datetime] = None,
    serial_number: Optional[int] = None,
    basic_constraints: Optional[BasicConstraints] = None,
    digestmod: Optional[hashlib.Algorithm] = None,
    csr_key_pair: Optional[Tuple[CSR, _PKey]] = None,
) -> Tuple[CRT, _PKey]:
    if subject is None:
        subject = "OU=test, CN=Intermediate Cert"
    if not_before is None:
        not_before = dt.datetime.utcnow()
    if not_after is None:
        not_after = not_before + dt.timedelta(days=90)
    if serial_number is None:
        serial_number = 0x123456
    if basic_constraints is None:
        basic_constraints = BasicConstraints(True, -1)
    if digestmod is None:
        digestmod = hashlib.sha256
    if csr_key_pair is None:
        csr, key = make_csr(subject=subject, digestmod=digestmod)

    return (
        issuer_crt.sign(
            csr,
            issuer_key,
            not_before,
            not_after,
            serial_number,
            basic_constraints,
        ),
        key,
    )


def make_crl() -> CRL:
    return CRL.from_PEM(CRL_PEM)


class TestCertificate:
    @pytest.fixture(
        scope="class", params=(make_csr()[0], make_root_ca()[0], make_crl())
    )
    def cert(self, request: Any) -> Union[CSR, CRT, CRL]:
        assert (
            isinstance(request.param, CSR)
            or isinstance(request.param, CRT)
            or isinstance(request.param, CRL)
        )
        return request.param

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self, repr_: Callable[[object], str], cert: Union[CSR, CRT, CRL]
    ) -> None:
        assert isinstance(repr_(cert), str)

    def test_pickle(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert cert == pickle.loads(pickle.dumps(cert))

    def test_hash(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert isinstance(hash(cert), int)

    def test_from_buffer(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert type(cert).from_buffer(cert.to_DER()) == cert

    def test_from_file(self, cert: Union[CSR, CRT, CRL], tmpdir: Any) -> None:
        path = tmpdir.join("key.der")
        path.write_binary(cert.to_DER())
        assert type(cert).from_file(path) == cert

    def test_from_DER(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert type(cert).from_DER(cert.to_DER()) == cert

    def test_eq_DER(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert cert == cert.to_DER()
        assert cert.to_DER() == cert

    def test_eq_PEM(self, cert: Union[CSR, CRT, CRL]) -> None:
        assert cert == cert.to_PEM()
        assert cert.to_PEM() == cert

    def test_empty_PEM_raises_ValueError(
        self, cert: Union[CSR, CRT, CRL]
    ) -> None:
        with pytest.raises(ValueError):
            type(cert).from_PEM("")

    def test_empty_DER_raises_ValueError(
        self, cert: Union[CSR, CRT, CRL]
    ) -> None:
        with pytest.raises(ValueError):
            type(cert).from_DER(b"")


class TestCRT:
    @pytest.mark.parametrize(
        "basic_constraints", [(True, 0), (True, 2), (False, 0)]
    )
    def test_accessor(
        self, now: dt.datetime, basic_constraints: BasicConstraints
    ) -> None:
        not_before = now
        not_after = now + dt.timedelta(days=90)
        issuer = "C=NL, O=PolarSSL, CN=PolarSSL Test CA"
        issuer_key = RSA()
        issuer_key.generate(key_size=1024)
        subject = "C=NL"
        subject_key = RSA()
        subject_key.generate(key_size=1024)
        serial_number = 0x1234567890
        digestmod = hashlib.sha256()

        crt = CRT.new(
            not_before=not_before,
            not_after=not_after,
            issuer=issuer,
            issuer_key=issuer_key,
            subject=subject,
            subject_key=subject_key,
            serial_number=serial_number,
            digestmod=digestmod,
            basic_constraints=basic_constraints,
        )

        assert crt.not_before == not_before
        assert crt.not_after == not_after
        assert crt.issuer == issuer
        assert crt.serial_number == serial_number
        assert crt.subject == "C=NL"
        assert crt.subject_public_key == subject_key.export_public_key(
            format="DER"
        )
        assert crt.basic_constraints == basic_constraints

    def test_public_key(self) -> None:
        crt, key = make_root_ca()
        pem = crt.subject_public_key.export_public_key(format="PEM")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
        assert pem.rstrip("\0").endswith("-----END PUBLIC KEY-----\n")
        assert pem == key.export_public_key(format="PEM")

    def test_revocation_bad_cast(self) -> None:
        crt, _key = make_root_ca()
        copy = CRT.from_buffer(crt.to_DER())
        with pytest.raises(TypeError):
            copy.check_revocation(crt)  # type: ignore[arg-type]

    def test_next(self) -> None:
        crt = CRT.from_file(certifi.where())
        with pytest.raises(StopIteration):
            while True:
                crt = next(crt)


class TestCSR:
    def test_accessors(self) -> None:
        subject = "C=NL, O=PolarSSL, CN=PolarSSL Server 1"
        subject_key = RSA()
        subject_key.generate(key_size=1024)

        csr, _k = make_csr(
            key=subject_key,
            subject=subject,
        )

        assert csr.version == 1
        assert csr.subject == subject
        assert csr.subject_public_key == subject_key.export_public_key()


class TestCRL:
    def test_accessors(self) -> None:
        crl = make_crl()

        assert crl.version == 1
        assert crl.issuer_name == "C=NL, O=PolarSSL, CN=PolarSSL Test CA"
        assert crl.this_update == dt.datetime(2011, 2, 20, 10, 22, 59)
        assert crl.next_update == dt.datetime(2019, 11, 25, 10, 22, 59)

        assert isinstance(crl.tbs_certificate, bytes)
        assert crl.tbs_certificate
        assert isinstance(crl.signature_value, bytes)
        assert crl.signature_value

    def test_revoked_certificates(self) -> None:
        crl = make_crl()
        assert len(crl.revoked_certificates) == 2

        entry = crl.revoked_certificates[0]
        assert entry.revocation_date == dt.datetime(2011, 2, 12, 14, 44, 7)
        assert entry.serial == 1

    @pytest.mark.skip("not implemented")
    def test_revocation_false(self, der: _DER) -> None:
        pass
        # crt = CRT.from_buffer(der)
        # crl = CRL.from_buffer(crl_der)
        # assert crt.check_revocation(crl) is False

    @pytest.mark.skip("not implemented")
    def test_crt_revocation_true(self, der: _DER) -> None:
        pass


class TestVerifyCertificateChain:
    def test_verify_chain(self) -> None:
        crt0, key0 = make_root_ca()
        crt1, key1 = make_crt(crt0, key0)
        crt2, key2 = make_crt(crt1, key1)

        assert crt0.verify(crt0) is True
        assert crt1.verify(crt2) is True
        assert crt2.verify(crt0) is False
