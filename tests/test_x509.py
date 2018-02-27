import base64
import datetime as dt
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

import pytest

from mbedtls.pk import RSA
from mbedtls import hash
from mbedtls.x509 import *


@pytest.fixture
def now():
    return dt.datetime.utcnow()


@pytest.fixture
def issuer_key():
    issuer_key  = RSA()
    issuer_key.generate(key_size=1024)
    return issuer_key


@pytest.fixture
def subject_key():
    subject_key = RSA()
    subject_key.generate(key_size=1024)
    return subject_key


class TestCRT:

    @pytest.fixture
    def crt_pem(self):
        with (Path(__file__).parent / "ca/wikipedia.pem").open() as crt:
            return crt.read()

    @pytest.fixture
    def crt_der(self, crt_pem):
        return PEM_to_DER(crt_pem)

    def test_from_buffer(self, crt_der):
        crt = Certificate.from_buffer(crt_der)
        assert "wikipedia.org" in crt._info()

    def test_from_DER(self, crt_der):
        crt = Certificate.from_DER(crt_der)
        assert "wikipedia.org" in crt._info()

    def test_from_PEM(self, crt_pem):
        crt = Certificate.from_PEM(crt_pem)
        assert crt.to_PEM() == crt_pem

    def test_from_file(self, crt_der, tmpdir):
        path = tmpdir.join("key.der")
        path.write_binary(crt_der)
        crt = Certificate.from_file(path)
        assert "wikipedia.org" in crt._info()

    def test_to_DER(self, crt_der):
        crt = Certificate.from_DER(crt_der)
        assert crt.to_DER() == crt_der

    def test_to_PEM(self, crt_pem):
        crt = Certificate.from_PEM(crt_pem)
        assert crt.to_PEM() == crt_pem

    def test_new(self, now, issuer_key, subject_key):
        crt = Certificate.new(
            start=now,
            end=now + dt.timedelta(days=90),
            issuer="C=NL,O=PolarSSL,CN=PolarSSL Test CA",
            issuer_key=issuer_key,
            subject="",
            subject_key=subject_key,
            serial=0x1234567890,
            md_alg=hash.sha1())
        assert "12:34:56:78:90" in crt._info()

    def test_revocation_bad_cast(self, crt_der):
        crt = Certificate.from_buffer(crt_der)
        with pytest.raises(TypeError):
            crt.check_revocation(crt)


class TestCRTWriter:

    @pytest.fixture
    def crt_writer(self, now, issuer_key, subject_key):
        return CertificateWriter(
            start=now, end=now + dt.timedelta(days=90),
            issuer="C=NL,O=PolarSSL,CN=PolarSSL Test CA", issuer_key=issuer_key,
            subject=None, subject_key=subject_key,
            md_alg=hash.sha1(),
            serial=None)

    def test_to_pem(self, crt_writer):
        pem = crt_writer.to_PEM()
        assert pem == crt_writer.to_PEM()
        assert pem.splitlines()[0] == "-----BEGIN CERTIFICATE-----"
        assert pem.splitlines()[-1] == "-----END CERTIFICATE-----"

    def test_to_der(self, crt_writer):
        assert PEM_to_DER(crt_writer.to_PEM()) == crt_writer.to_DER()

    def test_to_bytes(self, crt_writer):
        assert crt_writer.to_DER() == crt_writer.to_bytes()

    def test_to_certificate(self, crt_writer):
        crt = crt_writer.to_certificate()
        assert "cert. version" in crt._info()
        assert "PolarSSL" in crt._info()

    def test_set_serial(self, crt_writer):
        assert "12:34:56:78:90" not in crt_writer.to_certificate()._info()

        serial = 0x1234567890
        crt_writer.set_serial(serial)
        assert "12:34:56:78:90" in crt_writer.to_certificate()._info()

    def test_set_subject(self, crt_writer):
        assert "Server 1" not in crt_writer.to_certificate()._info()

        subject = "C=NL,O=PolarSSL,CN=PolarSSL Server 1"
        crt_writer.set_subject(subject)
        assert "Server 1" in crt_writer.to_certificate()._info()


class TestCSR:

    @pytest.fixture
    def csr_pem(self, subject_key):
        return CSRWriter(subject_key, hash.sha1(),
                         "C=NL,O=PolarSSL,CN=PolarSSL Server 1").to_PEM()

    @pytest.fixture
    def csr_der(self, csr_pem):
        return PEM_to_DER(csr_pem)

    def test_from_buffer(self, csr_der):
        csr = CSR.from_buffer(csr_der)
        assert "PolarSSL" in csr._info()

    def test_from_DER(self, csr_der):
        csr = CSR.from_DER(csr_der)
        assert "PolarSSL" in csr._info()

    def test_from_PEM(self, csr_pem):
        csr = CSR.from_PEM(csr_pem)
        assert csr.to_PEM() == csr_pem

    def test_from_file(self, csr_der, tmpdir):
        path = tmpdir.join("key.der")
        path.write_binary(csr_der)
        csr = CSR.from_file(path)
        assert "PolarSSL" in csr._info()

    def test_to_DER(self, csr_der):
        csr = CSR.from_DER(csr_der)
        assert csr.to_DER() == csr_der

    def test_to_PEM(self, csr_pem):
        csr = CSR.from_PEM(csr_pem)
        assert csr.to_PEM() == csr_pem

    def test_new(self, subject_key):
        csr = CSR.new(subject_key, hash.sha1(),
                      "C=NL,O=PolarSSL,CN=PolarSSL Server 1")
        assert "PolarSSL" in csr._info()


class TestCSRWriter:

    @pytest.fixture
    def csr_writer(self, subject_key):
        return CSRWriter(subject_key, hash.sha1(),
                         "C=NL,O=PolarSSL,CN=PolarSSL Server 1")

    def test_to_pem(self, csr_writer):
        pem = csr_writer.to_PEM()
        assert pem == csr_writer.to_PEM()
        assert pem.splitlines()[0] == "-----BEGIN CERTIFICATE REQUEST-----"
        assert pem.splitlines()[-1] == "-----END CERTIFICATE REQUEST-----"

    def test_to_der(self, csr_writer):
        assert PEM_to_DER(csr_writer.to_PEM()) == csr_writer.to_DER()

    def test_to_bytes(self, csr_writer):
        assert csr_writer.to_DER() == csr_writer.to_bytes()

    def test_to_certificate(self, csr_writer):
        csr = csr_writer.to_certificate()


class TestCRL:

    @pytest.fixture
    def crl_pem(self):
        with (Path(__file__).parent / "ca/wp_crl.pem").open() as crl:
            return crl.read()

    @pytest.fixture
    def crl_der(self, crl_pem):
        return PEM_to_DER(crl_pem)

    @pytest.fixture
    def crt_pem(self):
        with (Path(__file__).parent / "ca/wikipedia.pem").open() as crt:
            return crt.read()

    @pytest.fixture
    def crt_der(self, crt_pem):
        return PEM_to_DER(crt_pem)

    def test_from_buffer(self, crl_der):
        crl = CRL.from_buffer(crl_der)
        assert "CRL version" in crl._info()

    def test_from_file(self, crl_der, tmpdir):
        path = tmpdir.join("key.der")
        path.write_binary(crl_der)
        crl = CRL.from_file(path)
        assert "CRL version" in crl._info()

    def test_from_DER(self, crl_der):
        crl = CRL.from_DER(crl_der)
        assert "CRL version" in crl._info()

    def test_from_PEM(self, crl_pem):
        crl = CRL.from_PEM(crl_pem)
        assert crl.to_PEM() == crl_pem

    def test_to_DER(self, crl_der):
        crl = CRL.from_DER(crl_der)
        assert crl.to_DER() == crl_der

    def test_to_PEM(self, crl_pem):
        crl = CRL.from_PEM(crl_pem)
        assert crl.to_PEM() == crl_pem

    def test_revocation_false(self, crl_der, crt_der):
        crt = Certificate.from_buffer(crt_der)
        crl = CRL.from_buffer(crl_der)
        assert crt.check_revocation(crl) is False

    @pytest.mark.skip("requires data")
    def test_crt_revocation_true(self, crl_der, crt_der):
        pass
