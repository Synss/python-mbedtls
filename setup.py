import ctypes
import ctypes.util
import os
import sys
from setuptools import setup, Extension, find_packages

version = "1.3.0"
mbedtls_version = "2.16.6"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


__mbedtls_version_info__ = tuple(map(int, mbedtls_version.split(".")))
__mbedtls_url__ = "https://tls.mbed.org"


if "--with-coverage" in sys.argv:
    sys.argv.remove("--with-coverage")
    COVERAGE = True
else:
    COVERAGE = False


setup_requires = [
    # Setuptools 18.0 properly handles Cython extensions.
    "setuptools >= 18.0",
    # Cython 0.28 handles const memoryviews.
    "cython >= 0.28.0",
]
install_requires = [
    "certifi",
    'contextlib2; python_version < "3.0"',
    'enum34 != 1.1.8; python_version < "3.0"',
    'pathlib2; python_version < "3.0"',
]
tests_require = [
    "readme_renderer",
    'contextlib2; python_version < "3.0"',
]


def mbedtls_version(lib):
    null = b"\0"
    output = 18 * null
    output_p = ctypes.c_char_p(output)
    lib.mbedtls_version_get_string_full(output_p)
    return output.strip(null).decode("ascii")


def mbedtls_version_info(lib):
    version = lib.mbedtls_version_get_number()
    return tuple(version >> shift & 0xFF for shift in (24, 16, 8))


def check_mbedtls_support(version, url):
    library = ctypes.util.find_library("mbedtls")
    if not library:
        sys.stderr.write("  Library not found{sep}".format(sep=os.linesep))
    try:
        lib = ctypes.cdll.LoadLibrary(library)
        sys.stdout.write(
            "  mbedtls version: {!s}{sep}".format(
                mbedtls_version(lib), sep=os.linesep
            )
        )
    except OSError as exc:
        lib = None
        sys.stderr.write("  {exc!s}{sep}".format(exc=exc, sep=os.linesep))
    if lib and mbedtls_version_info(lib) < version[:2]:
        message = (
            "  python-mbedtls requires at least mbedtls {major}.{minor}".format(
                major=version[0], minor=version[1]
            ),
            "  The latest version of mbedtls may be obtained from {url}.".format(
                url=url
            ),
            "",
        )
        sys.stderr.writelines(os.linesep.join(message))
        sys.exit(1)


def extensions(coverage=False):
    for dirpath, dirnames, filenames in os.walk("src"):
        for fn in filenames:
            root, ext = os.path.splitext(fn)
            if ext != ".pyx":
                continue
            mod = ".".join(dirpath.split(os.sep)[1:] + [root])
            extension = Extension(
                mod,
                [os.path.join(dirpath, fn)],
                library_dirs=os.environ.get("LIBRARY_PATH", "").split(":"),
                libraries=["mbedcrypto", "mbedtls", "mbedx509"],
                define_macros=[
                    ("CYTHON_TRACE", "1"),
                    ("CYTHON_TRACE_NOGIL", "1"),
                ]
                if coverage
                else [],
            )
            extension.cython_directives = {"language_level": "3str"}
            if coverage:
                extension.cython_directives["linetrace"] = True
            yield extension


def options(coverage=False):
    if coverage:
        return {}

    return {
        "build": {
            "build_base": os.sep.join(
                ("build", "%i.%i.%i" % sys.version_info[:3])
            )
        },
        "build_ext": {"cython_c_in_temp": True},
    }


def readme():
    with open("README.rst") as f:
        return f.read().replace(":math:", "")


if len(sys.argv) > 1 and any(
    (sys.argv[1].startswith("build"), sys.argv[1].startswith("bdist"))
):
    check_mbedtls_support(
        version=__mbedtls_version_info__, url=__mbedtls_url__
    )


setup(
    name="python-mbedtls",
    version=version,
    description=(
        "hash, hmac, RSA, ECC, X.509, TLS, DTLS, handshakes, and secrets "
        "with an mbed TLS back end"
    ),
    long_description=readme(),
    author="Mathias Laurin",
    author_email="Mathias.Laurin@github.com",
    license="MIT License",
    url="https://github.com/Synss/python-mbedtls",
    download_url=download_url,
    ext_modules=list(extensions(COVERAGE)),
    options=options(COVERAGE),
    package_dir={"": "src"},
    packages=find_packages("src"),
    setup_requires=setup_requires,
    install_requires=install_requires,
    tests_require=tests_require,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ],
)
