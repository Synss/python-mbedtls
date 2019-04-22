import base64
import datetime as dt

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

import certifi
import pytest

from mbedtls.pk import RSA, ECC
from mbedtls import hash
from mbedtls.x509 import *


CRL_PEM = """
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
def now():
    return dt.datetime.utcnow().replace(microsecond=0)


@pytest.fixture
def issuer_key():
    issuer_key = RSA()
    issuer_key.generate(key_size=1024)
    return issuer_key


@pytest.fixture
def subject_key():
    subject_key = RSA()
    subject_key.generate(key_size=1024)
    return subject_key


class _X509Base:
    # Derive and provide `x509`.

    @pytest.fixture
    def der(self, x509):
        return x509.to_DER()

    @pytest.fixture
    def pem(self, x509):
        return x509.to_PEM()


class _CommonTests(_X509Base):
    def test_from_buffer(self, x509, der):
        assert type(x509).from_buffer(der) == x509

    def test_from_file(self, x509, der, tmpdir):
        path = tmpdir.join("key.der")
        path.write_binary(der)
        assert type(x509).from_file(path) == x509

    def test_from_PEM_empty_buffer_raises_valueerror(self, x509):
        with pytest.raises(ValueError):
            type(x509).from_PEM("")

    def test_from_DER(self, x509, der):
        assert type(x509).from_DER(der) == x509

    def test_from_DER_empty_buffer_raises_valueerror(self, x509):
        with pytest.raises(ValueError):
            type(x509).from_DER(b"")

    def test_eq(self, x509):
        assert x509 == x509

    def test_eq_der(self, x509, der):
        assert x509 == der
        assert der == x509

    def test_eq_pem(self, x509, pem):
        assert x509 == pem
        assert pem == x509


class _CRTWikipediaBase(_X509Base):
    @pytest.fixture
    def x509(self):
        with (Path(__file__).parent / "ca/wikipedia.pem").open() as crt:
            return CRT(PEM_to_DER(crt.read()))

    @pytest.fixture
    def crt(self, x509):
        return x509


class TestCRTWikipediaBase(_CommonTests, _CRTWikipediaBase):
    pass


class TestCRTWikipediaAccessors(_CRTWikipediaBase):
    def test_issuer(self, crt):
        assert crt.issuer == ", ".join(
            (
                "C=US",
                "O=DigiCert Inc",
                "OU=www.digicert.com",
                "CN=DigiCert SHA2 High Assurance Server CA",
            )
        )

    def test_subject(self, crt):
        assert crt.subject == ", ".join(
            (
                "C=US",
                "ST=California",
                "L=San Francisco",
                "O=Wikimedia Foundation, Inc.",
                "CN=*.wikipedia.org",
            )
        )

    def test_subject_alternative_names(self, crt):
        assert "*.m.wikidata.org" in crt.subject_alternative_names
        assert len(crt.subject_alternative_names) == 41

    def test_key_usage(self, crt):
        assert crt.key_usage is KeyUsage.DIGITAL_SIGNATURE


class _CRTBase(_X509Base):
    @pytest.fixture
    def issuer(self):
        return "C=NL, O=PolarSSL, CN=PolarSSL Test CA"

    @pytest.fixture
    def subject(self):
        return "C=NL"

    @pytest.fixture
    def serial_number(self):
        return 0x1234567890

    @pytest.fixture
    def digestmod(self):
        return hash.sha256()

    @pytest.fixture
    def basic_constraints(self):
        return BasicConstraints(False, 0)

    @pytest.fixture
    def x509(
        self,
        now,
        issuer,
        issuer_key,
        subject,
        subject_key,
        serial_number,
        digestmod,
        basic_constraints,
    ):
        return CRT.new(
            not_before=now,
            not_after=now + dt.timedelta(days=90),
            issuer=issuer,
            issuer_key=issuer_key,
            subject=subject,
            subject_key=subject_key,
            serial_number=serial_number,
            digestmod=digestmod,
            basic_constraints=basic_constraints,
        )

    @pytest.fixture
    def crt(self, x509):
        return x509


class TestCRTBase(_CommonTests, _CRTBase):
    pass


class TestCRTAccessors(_CRTBase):
    def test_version(self, crt):
        assert crt.version == 3

    def test_not_before(self, crt, now):
        assert crt.not_before == now

    def test_not_after(self, crt, now):
        assert crt.not_after == now + dt.timedelta(days=90)

    def test_issuer(self, crt, issuer):
        assert crt.issuer == issuer

    def test_public_key(self, crt):
        pem = crt.subject_public_key.export_public_key(format="PEM")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
        assert pem.rstrip("\0").endswith("-----END PUBLIC KEY-----\n")

    def test_subject(self, crt, subject):
        assert crt.subject == subject

    def test_serial_number(self, crt, serial_number):
        assert crt.serial_number == serial_number

    def test_revocation_bad_cast(self, der):
        crt = CRT.from_buffer(der)
        with pytest.raises(TypeError):
            crt.check_revocation(crt)

    def test_next(self):
        crt = CRT.from_file(certifi.where())
        with pytest.raises(StopIteration):
            while True:
                crt = next(crt)


class TestCRTMDAlg(_CRTBase):
    @pytest.fixture(params=[hash.sha1, hash.sha256])
    def digestmod(self, request):
        return request.param()

    def test_digestmod(self, crt, digestmod):
        assert crt.digestmod.name == digestmod.name


class TestCRTCAPath(_CRTBase):
    @pytest.fixture(params=[(True, 0), (True, 2), (False, 0), None])
    def basic_constraints(self, request):
        return request.param

    def test_ca(self, crt, basic_constraints):
        if basic_constraints is None:
            basic_constraints = BasicConstraints()
        assert crt.basic_constraints == basic_constraints


class _CSRBase(_X509Base):
    @pytest.fixture
    def subject(self):
        return "C=NL, O=PolarSSL, CN=PolarSSL Server 1"

    @pytest.fixture
    def x509(self, subject, subject_key):
        return CSR.new(subject_key, subject, hash.sha1())

    @pytest.fixture
    def csr(self, x509):
        return x509


class TestCSRBase(_CommonTests, _CSRBase):
    pass


class TestCSRAccessors(_CSRBase):
    def test_version(self, csr):
        assert csr.version == 1

    def test_subject(self, csr, subject):
        assert csr.subject == subject

    def test_subject_public_key(self, csr, subject_key):
        assert csr.subject_public_key == subject_key.export_public_key()


class _CRLBase(_X509Base):
    @pytest.fixture
    def x509(self):
        return CRL.from_PEM(CRL_PEM)

    @pytest.fixture
    def crl(self, x509):
        return x509


class TestCRLBase(_CommonTests, _CRLBase):
    pass


class TestCRLAccessors(_CRLBase):
    def test_tbs_certificate(self, crl):
        assert isinstance(crl.tbs_certificate, bytes)
        assert crl.tbs_certificate

    def test_signature_value(self, crl):
        assert isinstance(crl.signature_value, bytes)
        assert crl.signature_value

    def test_version(self, crl):
        assert crl.version == 1

    def test_issuer_name(self, crl):
        assert crl.issuer_name == "C=NL, O=PolarSSL, CN=PolarSSL Test CA"

    def test_this_update(self, crl):
        assert crl.this_update == dt.datetime(2011, 2, 20, 10, 22, 59)

    def test_next_update(self, crl):
        assert crl.next_update == dt.datetime(2019, 11, 25, 10, 22, 59)

    def test_revoked_certificates(self, crl):
        assert len(crl.revoked_certificates) == 2
        entry = crl.revoked_certificates[0]
        assert entry.revocation_date == dt.datetime(2011, 2, 12, 14, 44, 7)
        assert entry.serial == 1


class TestCRL(_CRLBase):
    @pytest.mark.skip("not implemented")
    def test_revocation_false(self, der):
        pass
        # crt = CRT.from_buffer(der)
        # crl = CRL.from_buffer(crl_der)
        # assert crt.check_revocation(crl) is False

    @pytest.mark.skip("not implemented")
    def test_crt_revocation_true(self, der):
        pass


class TestVerifyCertificateChain:
    @pytest.fixture
    def ca0_key(self):
        ca0_key = RSA()
        ca0_key.generate()
        return ca0_key

    @pytest.fixture
    def ca1_key(self):
        ca1_key = ECC()
        ca1_key.generate()
        return ca1_key

    @pytest.fixture
    def ee0_key(self):
        ee0_key = ECC()
        ee0_key.generate()
        return ee0_key

    @pytest.fixture
    def ca0_crt(self, ca0_key, now):
        ca0_csr = CSR.new(ca0_key, "CN=Trusted CA", hash.sha256())
        return CRT.selfsign(
            ca0_csr,
            ca0_key,
            not_before=now,
            not_after=now + dt.timedelta(days=90),
            serial_number=0x123456,
            basic_constraints=BasicConstraints(True, -1),
        )

    @pytest.fixture
    def ca1_crt(self, ca1_key, ca0_crt, ca0_key, now):
        ca1_csr = CSR.new(ca1_key, "CN=Intermediate CA", hash.sha256())
        return ca0_crt.sign(
            ca1_csr,
            ca0_key,
            now,
            now + dt.timedelta(days=90),
            0x234567,
            basic_constraints=BasicConstraints(True, 1),
        )

    @pytest.fixture
    def ee0_crt(self, ee0_key, ca1_crt, ca1_key, now):
        ee0_csr = CSR.new(ee0_key, "CN=End Entity", hash.sha256())
        return ca1_crt.sign(
            ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x345678
        )

    def test_verify_chain(self, ca0_crt, ca1_crt, ee0_crt):
        assert all((ca1_crt.verify(ee0_crt), ca0_crt.verify(ca0_crt)))
