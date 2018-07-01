"""Structure and functions for parsing and writing X.509 certificates."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls.x509 as x509
cimport mbedtls.mpi as _mpi
cimport mbedtls.pk as _pk

import base64

from mbedtls.exceptions import *


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
    """X.509 certificate."""

    def __init__(self, buffer):
        if buffer is None:
            return  # Implementation detail.
        self._from_buffer(buffer)

    def __cinit__(self):
        """Initialize a certificate (chain)."""
        x509.mbedtls_x509_crt_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all certificate data."""
        x509.mbedtls_x509_crt_free(&self._ctx)

    def __hash__(self):
        return hash(self.to_DER())

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.to_DER() == other.to_DER()

    def __next__(self):
        if self._ctx.next == NULL or self._ctx.version == 0:
            raise StopIteration
        cdef mbedtls_x509_buf buf = self._ctx.next.raw
        return type(self).from_DER(buf.p[0:buf.len])

    def _info(self):
        cdef size_t osize = 2**24
        cdef char* output = <char*>malloc(osize * sizeof(char))
        cdef char* prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_crt_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    cpdef _from_buffer(self, const unsigned char[:] buf):
        check_error(
            x509.mbedtls_x509_crt_parse(&self._ctx, &buf[0], buf.size))
        return self

    def check_revocation(self, CRL crl):
        """Return True if the certificate is revoked, False otherwise."""
        return bool(x509.mbedtls_x509_crt_is_revoked(&self._ctx, &crl._ctx))

    @classmethod
    def from_buffer(cls, buffer):
        # PEP 543
        return cls(None)._from_buffer(buffer)

    @classmethod
    def from_file(cls, path):
        # PEP 543, test pathlib
        path_ = str(path).encode("utf8")
        cdef const char* c_path = path_
        cdef Certificate self = cls(None)
        check_error(x509.mbedtls_x509_crt_parse_file(&self._ctx, c_path))
        return self

    @classmethod
    def from_DER(cls, const unsigned char[:] buffer):
        cdef Certificate self = cls(None)
        check_error(x509.mbedtls_x509_crt_parse_der(
            &self._ctx, &buffer[0], buffer.size))
        return self

    def to_DER(self):
        return bytes(self._ctx.raw.p[0:self._ctx.raw.len])

    __bytes__ = to_bytes = to_DER

    @classmethod
    def from_PEM(cls, pem):
        return cls.from_DER(PEM_to_DER(pem))

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "Certificate")

    __str__ = to_PEM

    def export(self, format="DER"):
        if format == "DER":
            return self.to_DER()
        if format == "PEM":
            return self.to_PEM()
        raise ValueError(format)

    @staticmethod
    def new(start, end, issuer, issuer_key, subject, subject_key,
            serial, md_alg):
        """Return a new certificate."""
        return _CertificateWriter(
            start, end, issuer, issuer_key,
            subject, subject_key, serial, md_alg).to_certificate()


cdef class _CertificateWriter:
    """CRT writing context.

    This class should not be used directly.
    Use `Certificate.new()` instead.

    """

    def __init__(self, start, end, issuer, issuer_key,
                 subject, subject_key, serial, md_alg):
        super(_CertificateWriter, self).__init__()
        self.set_validity(start, end)
        self.set_issuer(issuer)
        self.set_issuer_key(issuer_key)
        self.set_subject(subject)
        self.set_subject_key(subject_key)
        self.set_serial(serial)
        self.set_algorithm(md_alg)

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
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509write_crt_der(
                &self._ctx, &output[0], osize, NULL, NULL))
            return bytes(output[osize - written:osize])
        finally:
            free(output)

    to_bytes = to_DER

    def to_PEM(self):
        """Return the Certificate in PEM format.

        Warning:
            No RNG function is used.

        """
        cdef size_t osize = 4096
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(x509.mbedtls_x509write_crt_pem(
                &self._ctx, &output[0], osize, NULL, NULL))
            return output.decode("ascii")
        finally:
            free(output)

    __str__ = to_PEM

    def to_certificate(self):
        """Return a Certificate object."""
        return Certificate.from_DER(self.to_DER())

    def set_version(self, version=3):
        """Set the version for a certificate.

        Arg:
           version (int): The version between 1 and 3.

        """
        if version not in range(1, 4):
            raise ValueError("version not between 1 and 3")
        x509.mbedtls_x509write_crt_set_version(&self._ctx, version - 1)

    def set_serial(self, serial):
        """Set the serial number for a certificate.

        Arg:
            serial (int or bytes): The serial number.

        """
        if not serial:
            return
        cdef _mpi.MPI ser = _mpi.MPI(serial)
        x509.mbedtls_x509write_crt_set_serial(&self._ctx, &ser._ctx)

    def set_validity(self, start, end):
        """Set the validity period for a certificate.

        Args:
            start (datetime): Begin timestamp.
            end (datetime): End timestamp.

        """
        fmt = "%Y%m%d%H%M%S"
        # Keep reference to Python objects.
        start_ = start.strftime(fmt).encode("ascii")
        end_ = end.strftime(fmt).encode("ascii")
        cdef const char* c_start = start_
        cdef const char* c_end = end_
        check_error(x509.mbedtls_x509write_crt_set_validity(
            &self._ctx, c_start, c_end))

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

    def set_algorithm(self, md_alg):
        """Set MD algorithm to use for the signature.

        Args:
            md_alg (MDBase): MD algorithm, for ex. `hash.sha1()`.

        """
        x509.mbedtls_x509write_crt_set_md_alg(&self._ctx, md_alg._type)

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


cdef class CSR:
    """X.509 certificate signing request parser."""

    def __init__(self, buffer):
        super(CSR, self).__init__()
        if buffer is None:
            return  # Implementation detail.
        self._from_buffer(buffer)

    def __cinit__(self):
        """Initialize a CSR."""
        x509.mbedtls_x509_csr_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all CSR data."""
        x509.mbedtls_x509_csr_free(&self._ctx)

    def __hash__(self):
        return hash(self.to_DER())

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.to_DER() == other.to_DER()

    def _info(self):
        cdef size_t osize = 2**24
        cdef char* output = <char*>malloc(osize * sizeof(char))
        cdef char* prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_csr_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    cpdef _from_buffer(self, const unsigned char[:] buf):
        check_error(
            x509.mbedtls_x509_csr_parse(&self._ctx, &buf[0], buf.size))
        return self

    @classmethod
    def from_buffer(cls, buffer):
        # PEP 543
        return cls(None)._from_buffer(buffer)

    @classmethod
    def from_file(cls, path):
        # PEP 543, test pathlib
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

    __bytes__ = to_bytes = to_DER

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "Certificate Request")

    __str__ = to_PEM

    def export(self, format="DER"):
        if format == "DER":
            return self.to_DER()
        if format == "PEM":
            return self.to_PEM()
        raise ValueError(format)

    @staticmethod
    def new(key, md_alg, subject):
        """Return a new CSR."""
        return _CSRWriter(key, md_alg, subject).to_certificate()


cdef class _CSRWriter:
    """X.509 CSR writing context.

    This class should not be used directly.  Use `CSR.new()` instead.

    """
    def __init__(self, key, md_alg, subject):
        super(_CSRWriter, self).__init__()
        self.set_key(key)
        self.set_algorithm(md_alg)
        self.set_subject(subject)

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

    def set_key(self, _pk.CipherBase key):
        """Set the key for the CSR.

        Args:
            key (CipherBase): Asymetric key to include.

        """
        x509.mbedtls_x509write_csr_set_key(&self._ctx, &key._ctx)

    def set_algorithm(self, md_alg):
        """Set MD algorithm to use for the signature.

        Args:
            md_alg (MDBase): MD algorithm, for ex. `hash.sha1()`.

        """
        x509.mbedtls_x509write_csr_set_md_alg(&self._ctx, md_alg._type)

    def to_DER(self):
        """Return the CSR in DER format.

        Warning:
            No RNG function is used.

        """
        cdef size_t osize = 4096
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509write_csr_der(
                &self._ctx, &output[0], osize, NULL, NULL))
            return bytes(output[osize - written:osize])
        finally:
            free(output)

    to_bytes = to_DER

    def to_PEM(self):
        """Return the CSR in PEM format.

        Warning:
            No RNG function is used.

        """
        cdef size_t osize = 4096
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError
        try:
            check_error(x509.mbedtls_x509write_csr_pem(
                &self._ctx, &output[0], osize, NULL, NULL))
            return output.decode("ascii")
        finally:
            free(output)

    __str__ = to_PEM

    def to_certificate(self):
        """Return a CSR object."""
        return CSR.from_DER(self.to_DER())


cdef class CRL:
    """X.509 revocation list."""

    def __init__(self, buffer):
        super(CRL, self).__init__()
        if buffer is None:
            return  # Implementation detail.
        self._from_buffer(buffer)

    def __cinit__(self):
        """Initialize a CRL (chain)."""
        x509.mbedtls_x509_crl_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate all CRL data."""
        x509.mbedtls_x509_crl_free(&self._ctx)

    def __hash__(self):
        return hash(self.to_DER())

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self.to_DER() == other.to_DER()

    def __next__(self):
        if self._ctx.next == NULL or self._ctx.version == 0:
            raise StopIteration
        cdef mbedtls_x509_buf buf = self._ctx.next.raw
        return type(self).from_DER(buf.p[0:buf.len])

    def _info(self):
        cdef size_t osize = 2**24
        cdef char* output = <char*>malloc(osize * sizeof(char))
        cdef char* prefix = b""
        if not output:
            raise MemoryError()
        try:
            written = check_error(x509.mbedtls_x509_crl_info(
                &output[0], osize, prefix, &self._ctx))
            return bytes(output[:written]).decode("utf8")
        finally:
            free(output)

    cpdef _from_buffer(self, const unsigned char[:] buf):
        check_error(
            x509.mbedtls_x509_crl_parse(&self._ctx, &buf[0], buf.size))
        return self

    @classmethod
    def from_buffer(cls, buffer):
        # PEP 543
        return cls(None)._from_buffer(buffer)

    @classmethod
    def from_file(cls, path):
        # PEP 543, test pathlib
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

    def to_DER(self):
        return bytes(self._ctx.raw.p[0:self._ctx.raw.len])

    __bytes__ = to_bytes = to_DER

    @classmethod
    def from_PEM(cls, pem):
        return cls.from_DER(PEM_to_DER(pem))

    def to_PEM(self):
        return DER_to_PEM(self.to_DER(), "X509 CRL")

    __str__ = to_PEM

    def export(self, format="DER"):
        if format == "DER":
            return self.to_DER()
        if format == "PEM":
            return self.to_PEM()
        raise ValueError(format)
