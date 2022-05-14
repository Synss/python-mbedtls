import datetime as dt
import pickle

import certifi  # type: ignore
import pytest  # type: ignore

from mbedtls import hashlib
from mbedtls.pk import ECC, RSA  # type: ignore
from mbedtls.x509 import CRL, CRT, CSR, BasicConstraints  # type: ignore

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


def make_csr(
    key=None,
    subject=None,
    digestmod=None,
):
    if key is None:
        key = RSA()
        key.generate()
    if subject is None:
        subject = "OU=test, CN=example.com"
    if digestmod is None:
        digestmod = hashlib.sha256
    return CSR.new(key, subject, digestmod()), key


def make_root_ca(
    subject=None,
    not_before=None,
    not_after=None,
    serial_number=None,
    basic_constraints=None,
    digestmod=None,
    csr_key_pair=None,
):
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

    crt = CRT.selfsign(
        csr=csr,
        issuer_key=key,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
        basic_constraints=basic_constraints,
    )
    return crt, key


def make_crl():
    return CRL.from_PEM(CRL_PEM)


class TestCertificate:
    @pytest.fixture(
        scope="class", params=(make_csr()[0], make_root_ca()[0], make_crl())
    )
    def cert(self, request):
        return request.param

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
    def test_repr(self, repr_, cert):
        assert isinstance(repr_(cert), str)

    def test_pickle(self, cert):
        assert cert == pickle.loads(pickle.dumps(cert))

    def test_hash(self, cert):
        assert isinstance(hash(cert), int)

    def test_from_buffer(self, cert):
        assert type(cert).from_buffer(cert.to_DER()) == cert

    def test_from_file(self, cert, tmpdir):
        path = tmpdir.join("key.der")
        path.write_binary(cert.to_DER())
        assert type(cert).from_file(path) == cert

    def test_from_DER(self, cert):
        assert type(cert).from_DER(cert.to_DER()) == cert

    def test_eq_DER(self, cert):
        assert cert == cert.to_DER()
        assert cert.to_DER() == cert

    def test_eq_PEM(self, cert):
        assert cert == cert.to_PEM()
        assert cert.to_PEM() == cert

    def test_empty_PEM_raises_ValueError(self, cert):
        with pytest.raises(ValueError):
            type(cert).from_PEM("")

    def test_empty_DER_raises_ValueError(self, cert):
        with pytest.raises(ValueError):
            type(cert).from_DER(b"")


class TestCRT:
    @pytest.fixture
    def issuer(self):
        return "C=NL, O=PolarSSL, CN=PolarSSL Test CA"

    @pytest.fixture
    def issuer_key(self):
        issuer_key = RSA()
        issuer_key.generate(key_size=1024)
        return issuer_key

    @pytest.fixture
    def subject(self):
        return "C=NL"

    @pytest.fixture
    def subject_key(self):
        subject_key = RSA()
        subject_key.generate(key_size=1024)
        return subject_key

    @pytest.fixture
    def serial_number(self):
        return 0x1234567890

    @pytest.fixture(params=[hashlib.sha1, hashlib.sha256])
    def digestmod(self, request):
        return request.param()

    @pytest.fixture(params=[(True, 0), (True, 2), (False, 0), None])
    def basic_constraints(self, request):
        return request.param

    @pytest.fixture
    def crt(
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

    def test_revocation_bad_cast(self, crt):
        crt = CRT.from_buffer(crt.to_DER())
        with pytest.raises(TypeError):
            crt.check_revocation(crt)

    def test_next(self):
        crt = CRT.from_file(certifi.where())
        with pytest.raises(StopIteration):
            while True:
                crt = next(crt)

    def test_digestmod(self, crt, digestmod):
        assert crt.digestmod.name == digestmod.name

    def test_ca(self, crt, basic_constraints):
        if basic_constraints is None:
            basic_constraints = BasicConstraints()
        assert crt.basic_constraints == basic_constraints


class TestCSR:
    @pytest.fixture
    def subject(self):
        return "C=NL, O=PolarSSL, CN=PolarSSL Server 1"

    @pytest.fixture
    def subject_key(self):
        subject_key = RSA()
        subject_key.generate(key_size=1024)
        return subject_key

    @pytest.fixture
    def csr(self, subject, subject_key):
        return CSR.new(subject_key, subject, hashlib.sha1())

    def test_version(self, csr):
        assert csr.version == 1

    def test_subject(self, csr, subject):
        assert csr.subject == subject

    def test_subject_public_key(self, csr, subject_key):
        assert csr.subject_public_key == subject_key.export_public_key()


class TestCRL:
    @pytest.fixture
    def crl(self):
        return CRL.from_PEM(CRL_PEM)

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
        ca0_csr = CSR.new(ca0_key, "CN=Trusted CA", hashlib.sha256())
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
        ca1_csr = CSR.new(ca1_key, "CN=Intermediate CA", hashlib.sha256())
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
        ee0_csr = CSR.new(ee0_key, "CN=End Entity", hashlib.sha256())
        return ca1_crt.sign(
            ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x345678
        )

    def test_verify_chain(self, ca0_crt, ca1_crt, ee0_crt):
        assert all((ca1_crt.verify(ee0_crt), ca0_crt.verify(ca0_crt)))
