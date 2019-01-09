"""Structure and functions for parsing and writing X.509 certificates."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls.x509 as x509
cimport mbedtls.mpi as _mpi
cimport mbedtls.pk as _pk

import base64
import datetime as dt
try:
    from contextlib import suppress
except ImportError:
    # Python 2.7
    from contextlib2 import suppress
from collections import namedtuple

import mbedtls.hash as hashlib
import mbedtls.mpi as _mpi
import mbedtls.pk as _pk
import mbedtls._md as _md
from mbedtls.exceptions import *

import enum


@enum.unique
class KeyUsage(enum.IntEnum):
    """Key Usage Extension.

    See Also:
        RFC 5280 - 4.2.1.3 Key Usage.

    """
    DIGITAL_SIGNATURE  = 0x80
    NON_REPUDIATION = 0x40
    KEY_ENCIPHERMENT  = 0x20
    DATA_ENCIPHERMENT = 0x10
    KEY_AGREEMENT = 0x08
    KEY_CERT_SIGN = 0x04
    CRL_SIGN = 0x02
    ENCIPHER_ONLY = 0x01
    DECIPHER_ONLY = 0x8000


def PEM_to_DER(pem):
    return base64.b64decode(
        b"".join(line.encode("ascii") for line in pem.splitlines()
                 if not line.startswith("-----")))


def DER_to_PEM(der, text):
    chunk_size = 64
    pem = base64.b64encode(der).decode("ascii")
    return "\n".join((
        "-----BEGIN %s-----" % text.upper(),
        "\n".join(pem[n:n+chunk_size] for n in range(0, len(pem), chunk_size)),
        "-----END %s-----" % text.upper(),
        ""))


cdef class Certificate:
    @classmethod
    def from_buffer(cls, buffer):
        # PEP 543
        return cls(buffer)

    @classmethod
    def from_file(cls, path):
        # PEP 543
        raise NotImplementedError

    @classmethod
    def from_DER(cls, der):
        raise NotImplementedError

    @classmethod
    def from_PEM(cls, pem):
        raise NotImplementedError

    def __hash__(self):
        return hash(self.to_DER())

    def __eq__(self, other):
        if type(other) is type(self):
            return self.to_DER() == other.to_DER()
        else:
            # Python 2.7: Explicitly call `bytes()` to avoid warning.
            with suppress(TypeError):
                return (self.to_PEM() == str(other)
                        or self.to_DER() == bytes(other))
        return False

    def __str__(self):
        raise NotImplementedError

    def __bytes__(self):
        return self.to_DER()

    def export(self, format="DER"):
        if format == "DER":
            return self.to_DER()
        if format == "PEM":
            return self.to_PEM()
        raise ValueError(format)

    def to_bytes(self):
        return self.to_DER()

    def to_DER(self):
        raise NotImplementedError

    def to_PEM(self):
        raise NotImplementedError


class BasicConstraints(
        namedtuple("BasicConstraints", ["ca", "max_path_length"])):
    """The basic constraints for the certificate."""

    def __new__(cls, ca=False, max_path_length=0):
        return super(BasicConstraints, cls).__new__(cls, ca, max_path_length)


cdef class CRT(Certificate):
    """X.509 certificate."""

    def __init__(self, const unsigned char[:] buffer):
        super(CRT, self).__init__()
        self._next = None
        if buffer is None:
            return
        check_error(x509.mbedtls_x509_crt_parse(
            &self._ctx, &buffer[0], buffer.size))

    def __cinit__(self):
        """Initialize a certificate (chain)."""
        x509.mbedtls_x509_crt_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all certificate data."""
        self.unset_next()
        x509.mbedtls_x509_crt_free(&self._ctx)

    def __next__(self):
        if self._next is None:
            raise StopIteration
        return self._next

    def __str__(self):
        cdef size_t osize = 2**24
        cdef char *output = <char *>malloc(osize * sizeof(char))
        cdef char *prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_crt_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    # RFC 5280, Section 4.1 Basic Certificate Fields
    # RFC 5280, Section 4.1.1 Certificate Fields

    @property
    def tbs_certificate(self):
        """The TBS (to be signed) certificate in DER format.

        See Also:
            RFC 5280, Section 4.1.1.1 TBS Certificate

        """
        return bytes(self._ctx.tbs.p[:self._ctx.tbs.len])

    @property
    def _signature_algorithm(self):
        """Cryptographic algorithm used by the CA to sign this CRT.

        See Also:
            RFC 5280, Section 4.1.1.2 Signature Algorithm

        """
        # The byte structure should be parsed according to RFC 5280.
        return bytes(self._ctx.sig_oid.p[:self._ctx.sig_oid.len])

    @property
    def signature_value(self):
        """Digital signature of the TBS certificate.

        See Also:
            RFC 5280, Section 4.1.1.3 Signature Value

        """
        return bytes(self._ctx.sig.p[:self._ctx.sig.len])

    # RFC 5280, Section 4.1.2 TBS Certificate

    @property
    def version(self):
        """The version of the encoded certificate.

        See Also:
            RF 5280, Section 4.1.2.1 Version

        """
        return int(self._ctx.version)

    @property
    def serial_number(self):
        """The certificate serial number.

        See Also:
            RFC 5280, Section 4.1.2.2 Serial Number

        """
        return int(_mpi.MPI.from_bytes(
            self._ctx.serial.p[:self._ctx.serial.len], "big"))

    # RFC 4.1.2.3 Signature
    @property
    def digestmod(self):
        return hashlib.new(
            _md.MD_NAME[self._ctx.sig_md].decode("ascii").lower())

    @property
    def issuer(self):
        """Entity that has signed and issued the certificate.

        See Also:
            RFC 5280, Section 4.1.2.4 Issuer

        """
        cdef size_t osize = 200
        cdef char* c_buf = <char *>malloc(osize * sizeof(char))
        if not c_buf:
            raise MemoryError()
        try:
            written = x509.mbedtls_x509_dn_gets(
                &c_buf[0], osize, &self._ctx.issuer)
            return bytes(c_buf[:written]).decode("utf8")
        finally:
            free(c_buf)

    @property
    def not_before(self):
        """Beginning of the validity of the certificate (inclusive).

        See Also:
            RFC 5280, Section 4.1.2.5 Validity

        """
        cdef x509.mbedtls_x509_time *valid_from = &self._ctx.valid_from
        return dt.datetime(
            valid_from[0].year, valid_from[0].mon, valid_from[0].day,
            valid_from[0].hour, valid_from[0].min, valid_from[0].sec)

    @property
    def not_after(self):
        """End of the validity of the certificate (inclusive).

        See Also:
            RFC 5280, Section 4.1.2.5 Validity

        """
        cdef x509.mbedtls_x509_time *valid_to = &self._ctx.valid_to
        return dt.datetime(
            valid_to[0].year, valid_to[0].mon, valid_to[0].day,
            valid_to[0].hour, valid_to[0].min, valid_to[0].sec)

    @property
    def subject(self):
        """Entity associated with the public key.

        See Also:
            RFC 5280, Section 4.1.2.6 Subject

        """
        cdef size_t osize = 200
        cdef char *c_buf = <char *>malloc(osize * sizeof(char))
        if not c_buf:
            raise MemoryError()
        try:
            written = x509.mbedtls_x509_dn_gets(
                &c_buf[0], osize, &self._ctx.subject)
            return bytes(c_buf[:written]).decode("utf8")
        finally:
            free(c_buf)

    @property
    def subject_public_key(self):
        """The public key.

        See Also:
            RFC 5280, Section 4.1.2.7 Subject Public Key Info

        """
        cipher_type = _pk.CipherType(_pk.mbedtls_pk_get_type(&self._ctx.pk))
        cipher = {
            _pk.CipherType.RSA: _pk.RSA,
            _pk.CipherType.ECKEY: _pk.ECC,
        }.get(cipher_type, None)
        if cipher is None:
            raise ValueError("unsupported cipher %r" % cipher_type)

        cdef size_t osize = _pk.PUB_DER_MAX_BYTES
        cdef unsigned char *c_buf = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not c_buf:
            raise MemoryError()
        try:
            ret = check_error(_pk.mbedtls_pk_write_pubkey_der(
                &self._ctx.pk, &c_buf[0], osize))
            return cipher.from_DER(c_buf[osize - ret:osize])
        finally:
            free(c_buf)

    # RFC 5280, Section 4.1.2.8 Unique Identifiers
    # RFC 5280, Section 4.1.2.9 Extensions
    # RFC 5280, Section 4.2 Certificate Extensions
    # RFC 5280, Section 4.2.1 Standard Extensions
    # RFC 5280, Section 4.2.1.1 Authority Key Identifier
    # RFC 5280, Section 4.2.1.2 Subject Key Identifier

    @property
    def key_usage(self):
        """Key usage extension (bitfield).

        See Also:
            RFC 5280, Section 4.2.1.3 Key Usage

        """
        return KeyUsage(self._ctx.key_usage)

    # RFC 5280, Section 4.2.1.4 Certificate Policies
    # RFC 5280, Section 4.2.1.5 Policy Mappings

    @property
    def subject_alternative_names(self):
        """Subject alternative name extension.

        See Also:
            RFC 5280, Section 4.2.1.6 Subject Alternative Name

        """
        cdef mbedtls_x509_sequence *item
        item = &self._ctx.subject_alt_names
        names = set()
        while item != NULL:
            names.add(item.buf.p[:item.buf.len].decode("utf8"))
            item = item.next
        return frozenset(names)

    # RFC 5280, Section 4.2.1.7 Issuer Alternative Name
    # RFC 5280, Section 4.2.1.8 Subject Directory Attributes

    @property
    def basic_constraints(self):
        """ca is true if the certified public key may be used
        to verify certificate signatures.

        See Also:
            - RFC 5280, Section 4.2.1.9 Basic Constraints
            - RFC 5280, `max_path_length`

        """
        max_path_length = int(self._ctx.max_pathlen)
        if max_path_length > 0:
            max_path_length -= 1
        ca = bool(self._ctx.ca_istrue)
        return BasicConstraints(ca, max_path_length)

    # RFC 5280, Section 4.2.1.10 Name Constraints
    # RFC 5280, Section 4.2.1.11 Policy Constraints
    # RFC 5280, Section 4.2.1.12 Extended Key Usage
    # RFC 5280, Section 4.2.1.13 CRL Distribution Points
    # RFC 5280, Section 4.2.1.14 Inhibit Any-Policy
    # RFC 5280, Section 4.2.1.15 Freshest CRL

    cdef set_next(self, CRT crt):
        self._next = crt
        self._ctx.next = &crt._ctx

    cdef unset_next(self):
        self._ctx.next = NULL
        self._next = None

    def check_revocation(self, CRL crl):
        """Return True if the certificate is revoked, False otherwise."""
        return bool(x509.mbedtls_x509_crt_is_revoked(&self._ctx, &crl._ctx))

    @classmethod
    def from_file(cls, path):
        path_ = str(path).encode("utf8")
        cdef const char* c_path = path_
        cdef CRT self = cls(None)
        check_error(x509.mbedtls_x509_crt_parse_file(&self._ctx, c_path))
        return self

    @classmethod
    def from_DER(cls, const unsigned char[:] buffer):
        cdef CRT self = cls(None)
        check_error(x509.mbedtls_x509_crt_parse_der(
            &self._ctx, &buffer[0], buffer.size))
        return self

    @classmethod
    def from_PEM(cls, pem):
        return cls.from_DER(PEM_to_DER(pem))

    def to_DER(self):
        return bytes(self._ctx.raw.p[0:self._ctx.raw.len])

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "Certificate")

    def sign(self, csr, issuer_key, not_before, not_after, serial_number,
             basic_constraints=BasicConstraints()):
        """Return a new, signed certificate for the CSR."""
        if not _pk.check_pair(
                self.subject_public_key,
                issuer_key):
            raise ValueError(
                "The issuer_key does not correspond to this certificate")
        cdef CRT crt = self.new(
            not_before=not_before,
            not_after=not_after,
            issuer=self.subject,
            issuer_key=issuer_key,
            subject=csr.subject,
            subject_key=csr.subject_public_key,
            serial_number=serial_number,
            digestmod=csr.digestmod,
            basic_constraints=basic_constraints)
        return crt

    @classmethod
    def selfsign(cls, csr, issuer_key, not_before, not_after, serial_number,
                 basic_constraints=BasicConstraints()):
        """Return a new, self-signed certificate for the CSR."""
        return cls.new(
            not_before=not_before,
            not_after=not_after,
            issuer=csr.subject,
            issuer_key=issuer_key,
            subject=csr.subject,
            subject_key=csr.subject_public_key,
            serial_number=serial_number,
            digestmod=csr.digestmod,
            basic_constraints=basic_constraints)

    def verify(self, crt):
        """Verify the certificate `crt`."""
        return self.subject_public_key.verify(
            crt.tbs_certificate, crt.signature_value, crt.digestmod.name)

    @staticmethod
    def new(not_before, not_after, issuer, issuer_key, subject, subject_key,
            serial_number, digestmod, basic_constraints=BasicConstraints()):
        """Return a new certificate."""
        return _CRTWriter(
            not_before, not_after, issuer, issuer_key,
            subject, subject_key, serial_number, digestmod,
            basic_constraints=basic_constraints).to_certificate()


cdef class _CRTWriter:
    """CRT writing context.

    This class should not be used directly.
    Use `CRT.new()` instead.

    """
    def __init__(self, not_before, not_after, issuer, issuer_key,
                 subject, subject_key, serial_number, digestmod,
                 basic_constraints=BasicConstraints()):
        super(_CRTWriter, self).__init__()
        self.set_validity(not_before, not_after)
        self.set_issuer(issuer)
        self.set_issuer_key(issuer_key)
        self.set_subject(subject)
        self.set_subject_key(subject_key)
        self.set_serial_number(serial_number)
        self.set_digestmod(digestmod)
        self.set_basic_constraints(basic_constraints)

    def __cinit__(self):
        """Initialize a CRT write context."""
        x509.mbedtls_x509write_crt_init(&self._ctx)

    def __dealloc__(self):
        """Free the contents of a CRT write context."""
        x509.mbedtls_x509write_crt_free(&self._ctx)

    def to_DER(self):
        """Return the certificate in DER format.

        Warning:
            No RNG function is used.

        """
        cdef size_t osize = 4096
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509write_crt_der(
                &self._ctx, &output[0], osize, NULL, NULL))
            return bytes(output[osize - written:osize])
        finally:
            free(output)

    def to_bytes(self):
        return self.to_DER()

    def to_certificate(self):
        """Return a Certificate object."""
        return CRT.from_DER(self.to_DER())

    def set_version(self, version=3):
        """Set the version for a certificate.

        Arg:
           version (int): The version between 1 and 3.

        """
        if version not in range(1, 4):
            raise ValueError("version not between 1 and 3")
        x509.mbedtls_x509write_crt_set_version(&self._ctx, version - 1)

    def set_serial_number(self, serial_number):
        """Set the serial number for a certificate.

        Arg:
            serial_number (int or bytes): The serial number.

        """
        if not serial_number:
            return
        cdef _mpi.MPI ser = _mpi.MPI(serial_number)
        x509.mbedtls_x509write_crt_set_serial(&self._ctx, &ser._ctx)

    def set_validity(self, not_before, not_after):
        """Set the validity period for a certificate.

        Args:
            not_before (datetime): Begin timestamp.
            not_after (datetime): End timestamp.

        """
        fmt = "%Y%m%d%H%M%S"
        # Keep reference to Python objects.
        not_before = not_before.strftime(fmt).encode("ascii")
        not_after = not_after.strftime(fmt).encode("ascii")
        cdef const char* c_not_before = not_before
        cdef const char* c_not_after = not_after
        check_error(x509.mbedtls_x509write_crt_set_validity(
            &self._ctx, c_not_before, c_not_after))

    def set_issuer(self, issuer):
        """Set the issuer name.

        Args:
            issuer (str): Comma-separated list of OID types and values:
                e.g. "C=UK,I=ARM,CN=mbed TLS CA"

        """
        # Keep reference to Python object.
        issuer_ = issuer.encode("utf8")
        cdef const char* c_issuer = issuer_
        check_error(x509.mbedtls_x509write_crt_set_issuer_name(
            &self._ctx, c_issuer))

    def set_subject(self, subject):
        """Set the subject name for a certificate.

        Args:
            subject (str): Subject name as a comma-separated list
                of OID types and values.
                e.g. "C=UK,O=ARM,CN=mbed TLS Server 1"

        """
        if subject is None:
            return
        # Keep reference to Python object.
        subject_ = subject.encode("utf8")
        cdef const char* c_subject = subject_
        check_error(x509.mbedtls_x509write_crt_set_subject_name(
            &self._ctx, c_subject))

    def set_digestmod(self, digestmod):
        """Set MD algorithm to use for the signature.

        Args:
            digestmod (MDBase): MD algorithm, for ex. `hash.sha1()`.

        """
        x509.mbedtls_x509write_crt_set_md_alg(&self._ctx, digestmod._type)

    def set_subject_key(self, _pk.CipherBase key):
        """Set the subject key.

        Args:
            key (CipherBase): Subject key.

        """
        x509.mbedtls_x509write_crt_set_subject_key(&self._ctx, &key._ctx)
        check_error(
            x509.mbedtls_x509write_crt_set_subject_key_identifier(&self._ctx))

    def set_issuer_key(self, _pk.CipherBase key):
        """Set the issuer key.

        Args:
            key (CipherBase): Issuer key.

        """
        x509.mbedtls_x509write_crt_set_issuer_key(
            &self._ctx, &key._ctx)
        check_error(
            x509.mbedtls_x509write_crt_set_authority_key_identifier(&self._ctx))

    def set_basic_constraints(self, basic_constraints):
        """Set the basic constraints extension for a CRT.

        Args:
            basic_constraints (BasicConstraints): The basic constraints.

        """
        if not basic_constraints:
            return
        check_error(x509.mbedtls_x509write_crt_set_basic_constraints(
            &self._ctx, int(basic_constraints[0]), basic_constraints[1]))


cdef class CSR(Certificate):
    """X.509 certificate signing request parser."""

    def __init__(self, const unsigned char[:] buffer):
        super(CSR, self).__init__()
        if buffer is None:
            return
        check_error(x509.mbedtls_x509_csr_parse(
            &self._ctx, &buffer[0], buffer.size))

    def __cinit__(self):
        """Initialize a CSR."""
        x509.mbedtls_x509_csr_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all CSR data."""
        x509.mbedtls_x509_csr_free(&self._ctx)

    def __str__(self):
        cdef size_t osize = 2**24
        cdef char *output = <char *>malloc(osize * sizeof(char))
        cdef char *prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_csr_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    @property
    def digestmod(self):
        """Return the hash function used for the signature.

        See Also:
            RFC5280, Section 4.1.1.2 Signature Algorithm.

        """
        return hashlib.new(
            _md.MD_NAME[self._ctx.sig_md].decode("ascii").lower())

    @property
    def version(self):
        """The version of the encoded certificate.

        See Also:
            RF 5280, Section 4.1.2.1 Version

        """
        return int(self._ctx.version)

    @property
    def subject(self):
        """Entity associated with the public key.

        See Also:
            RFC 5280, Section 4.1.2.6 Subject

        """
        cdef size_t osize = 200
        cdef char *c_buf = <char *>malloc(osize * sizeof(char))
        if not c_buf:
            raise MemoryError()
        try:
            written = x509.mbedtls_x509_dn_gets(
                &c_buf[0], osize, &self._ctx.subject)
            return bytes(c_buf[:written]).decode("utf8")
        finally:
            free(c_buf)

    @property
    def subject_public_key(self):
        """The public key.

        See Also:
            RFC 5280, Section 4.1.2.7 Subject Public Key Info

        """
        cipher_type = _pk.CipherType(_pk.mbedtls_pk_get_type(&self._ctx.pk))
        cipher = {
            _pk.CipherType.RSA: _pk.RSA,
            _pk.CipherType.ECKEY: _pk.ECC,
        }.get(cipher_type, None)
        if cipher is None:
            raise ValueError("unsupported cipher %r" % cipher_type)

        cdef size_t osize = _pk.PUB_DER_MAX_BYTES
        cdef unsigned char *c_buf = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not c_buf:
            raise MemoryError()
        try:
            ret = check_error(_pk.mbedtls_pk_write_pubkey_der(
                &self._ctx.pk, &c_buf[0], osize))
            return cipher.from_DER(c_buf[osize - ret:osize])
        finally:
            free(c_buf)

    @classmethod
    def from_file(cls, path):
        path_ = str(path).encode("utf8")
        cdef const char* c_path = path_
        cdef CSR self = cls(None)
        check_error(x509.mbedtls_x509_csr_parse_file(&self._ctx, c_path))
        return self

    @classmethod
    def from_DER(cls, const unsigned char[:] buffer):
        cdef CSR self = cls(None)
        check_error(x509.mbedtls_x509_csr_parse_der(
            &self._ctx, &buffer[0], buffer.size))
        return self

    @classmethod
    def from_PEM(cls, pem):
        return cls.from_DER(PEM_to_DER(pem))

    def to_DER(self):
        return bytes(self._ctx.raw.p[0:self._ctx.raw.len])

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "Certificate Request")

    @staticmethod
    def new(subject_key, subject, digestmod):
        """Return a new CSR."""
        return _CSRWriter(subject_key, subject, digestmod).to_certificate()


cdef class _CSRWriter:
    """X.509 CSR writing context.

    This class should not be used directly.  Use `CSR.new()` instead.

    """
    def __init__(self, subject_key, subject, digestmod):
        super(_CSRWriter, self).__init__()
        self.set_subject_key(subject_key)
        self.set_subject(subject)
        self.set_digestmod(digestmod)

    def __cinit__(self):
        """Initialize a CSR context."""
        x509.mbedtls_x509write_csr_init(&self._ctx)

    def __dealloc__(self):
        """Free the contents of a CSR context."""
        x509.mbedtls_x509write_csr_free(&self._ctx)

    def set_subject(self, subject):
        """Set the subject name for a CSR.

        Args:
            subject (str): Subject name as a comma-separated list
                of OID types and values.
                e.g. "C=UK,O=ARM,CN=mbed TLS Server 1"

        """
        if not subject:
            return
        # Keep reference to Python object.
        subject_ = subject.encode("utf8")
        cdef const char* c_subject = subject_
        check_error(x509.mbedtls_x509write_csr_set_subject_name(
            &self._ctx, c_subject))

    def set_subject_key(self, _pk.CipherBase key):
        """Set the key for the CSR.

        Args:
            key (CipherBase): Asymetric key to include.

        """
        x509.mbedtls_x509write_csr_set_key(&self._ctx, &key._ctx)

    def set_digestmod(self, digestmod):
        """Set MD algorithm to use for the signature.

        Args:
            digestmod (MDBase): MD algorithm, for ex. `hash.sha1()`.

        """
        x509.mbedtls_x509write_csr_set_md_alg(&self._ctx, digestmod._type)

    def to_DER(self):
        """Return the CSR in DER format.

        Warning:
            No RNG function is used.

        """
        cdef size_t osize = 4096
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509write_csr_der(
                &self._ctx, &output[0], osize, NULL, NULL))
            return bytes(output[osize - written:osize])
        finally:
            free(output)

    def to_bytes(self):
        return self.to_DER()

    def to_certificate(self):
        """Return a CSR object."""
        return CSR.from_DER(self.to_DER())


class CRLEntry(namedtuple("CRLEntry", ["serial", "revocation_date"])):
    """An entry in the revocation list."""


cdef class CRL(Certificate):
    """X.509 revocation list."""

    def __init__(self, const unsigned char[:] buffer):
        super(CRL, self).__init__()
        self._next = None
        if buffer is None:
            return
        check_error(x509.mbedtls_x509_crl_parse(
            &self._ctx, &buffer[0], buffer.size))

    def __cinit__(self):
        """Initialize a CRL (chain)."""
        x509.mbedtls_x509_crl_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all CRL data."""
        self.unset_next()
        x509.mbedtls_x509_crl_free(&self._ctx)

    def __next__(self):
        if self._next is None:
            raise StopIteration
        return self._next

    def __str__(self):
        cdef size_t osize = 2**24
        cdef char *output = <char *>malloc(osize * sizeof(char))
        cdef char *prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_crl_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    # RFC 5280, Section 5.1 CRL Fields
    # RFC 5280, Section 5.1.1 Certificate List Fields
    @property
    def tbs_certificate(self):
        """The TBS (to be signed) certificate in DER format.

        See Also:
            RFC 5280, Section 5.1.1.1 TBS Certificate

        """
        return bytes(self._ctx.tbs.p[:self._ctx.tbs.len])

    # RFC 5280, Section 5.1.1.2 Signature Algorithm

    @property
    def signature_value(self):
        """Cryptographic algorithm used by the CA to sign this CRL.

        See Also:
            RFC 5280, Section 5.1.1.3 Signature Algorithm

        """
        return bytes(self._ctx.sig.p[:self._ctx.sig.len])

    # RFC 5280, Section 5.1.2 Certificate List "To Be Signed"

    @property
    def version(self):
        """The version of the encoded certificate.

        See Also:
            RF 5280, Section 5.1.2.1 Version

        """
        return int(self._ctx.version)

    # RFC 5280, Section 5.1.2.2 Signature

    @property
    def issuer_name(self):
        """Entity that has signed and issued the certificate.

        See Also:
            RFC 5280, Section 5.1.2.3 Issuer Name

        """
        cdef size_t osize = 200
        cdef char* c_buf = <char *>malloc(osize * sizeof(char))
        if not c_buf:
            raise MemoryError()
        try:
            written = x509.mbedtls_x509_dn_gets(
                &c_buf[0], osize, &self._ctx.issuer)
            return bytes(c_buf[:written]).decode("utf8")
        finally:
            free(c_buf)

    @property
    def this_update(self):
        """The issue date of this certificate.

        See Also:
            RFC 5280, Section 5.1.2.4 This Update

        """
        cdef x509.mbedtls_x509_time *this_update = &self._ctx.this_update
        return dt.datetime(
            this_update[0].year, this_update[0].mon, this_update[0].day,
            this_update[0].hour, this_update[0].min, this_update[0].sec)

    @property
    def next_update(self):
        """The date by which the next certificate will be issued.

        See Also:
            RFC 5280, Section 5.1.2.5 Next Update

        """
        cdef x509.mbedtls_x509_time *next_update = &self._ctx.next_update
        return dt.datetime(
            next_update[0].year, next_update[0].mon, next_update[0].day,
            next_update[0].hour, next_update[0].min, next_update[0].sec)

    @property
    def revoked_certificates(self):
        """The list of revoked certificates.

        See Also:
            RFC 5280, Section 5.1.2.6 Revoked Certificates

        """
        cdef x509.mbedtls_x509_crl_entry *item
        item = &self._ctx.entry
        revoked = []
        while item != NULL:
            revoked.append(CRLEntry(
                int(_mpi.MPI.from_bytes(
                    item.serial.p[:item.serial.len], "big")),
                dt.datetime(
                    item.revocation_date.year,
                    item.revocation_date.mon,
                    item.revocation_date.day,
                    item.revocation_date.hour,
                    item.revocation_date.min,
                    item.revocation_date.sec)))
            item = item.next
        return tuple(revoked)

    @classmethod
    def from_file(cls, path):
        path_ = str(path).encode("utf8")
        cdef const char* c_path = path_
        cdef CRL self = cls(None)
        check_error(x509.mbedtls_x509_crl_parse_file(&self._ctx, c_path))
        return self

    @classmethod
    def from_DER(cls, const unsigned char[:] buffer):
        cdef CRL self = cls(None)
        check_error(x509.mbedtls_x509_crl_parse_der(
            &self._ctx, &buffer[0], buffer.size))
        return self

    @classmethod
    def from_PEM(cls, pem):
        return cls.from_DER(PEM_to_DER(pem))

    def to_DER(self):
        return bytes(self._ctx.raw.p[0:self._ctx.raw.len])

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "X509 CRL")

    cdef set_next(self, CRL crl):
        self._next = crl
        self._ctx.next = &crl._ctx

    cdef unset_next(self):
        self._ctx.next = NULL
        self._next = None
