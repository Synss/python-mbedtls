# SPDX-License-Identifier: MIT

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import re
import sys
from contextlib import suppress

from setuptools import Extension, find_packages, setup  # type: ignore


def _get_version():
    pattern = re.compile(r'^__version__ = ["]([.\w]+?)["]')
    with open(
        os.path.join(
            os.path.dirname(__file__), "src", "mbedtls", "__init__.py"
        )
    ) as f:
        for line in f:
            match = pattern.match(line)
            if match:
                return match.group(1)
        raise RuntimeError()


VERSION = _get_version()
MBEDTLS_VERSION = "2.28.1"
DOWNLOAD_URL = "https://github.com/Synss/python-mbedtls/tarball/%s" % VERSION


__mbedtls_version_info__ = tuple(map(int, MBEDTLS_VERSION.split(".")))
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
    "typing_extensions",
]
tests_require = [
    "readme_renderer",
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
        sys.stderr.write(f"  Library not found{os.linesep}")
        sys.stderr.write(
            "  The paths are probably not set correctly but let's try anyway{sep}".format(
                sep=os.linesep
            )
        )
        return
    try:
        lib = ctypes.cdll.LoadLibrary(library)
        sys.stdout.write(f"  loading: {lib._name!r}\n")
        sys.stdout.write(
            "  mbedtls version: {!s}{sep}".format(
                mbedtls_version(lib), sep=os.linesep
            )
        )
        sys.stdout.write(f"  python-mbedtls version: {VERSION}\n")
    except OSError as exc:
        lib = None
        sys.stderr.write(f"  {exc!s}{os.linesep}")
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
    def from_env(var):
        with suppress(KeyError):
            return filter(None, os.environ[var].split(ENVSEP))
        return ()

    WINDOWS = platform.system() == "Windows"
    ENVSEP = ";" if WINDOWS else ":"

    libraries = (
        [
            "AdvAPI32",  # `Crypt*` calls from `library/entropy_poll.c`
            "mbedTLS",
        ]
        if WINDOWS
        else ["mbedcrypto", "mbedtls", "mbedx509"]
    )
    library_dirs = list(from_env("LIB" if WINDOWS else "LIBRARY_PATH"))

    for dirpath, _, filenames in os.walk("src"):
        for fn in filenames:
            root, ext = os.path.splitext(fn)
            if ext != ".pyx":
                continue
            mod = ".".join(dirpath.split(os.sep)[1:] + [root])
            extension = Extension(
                mod,
                sources=[os.path.join(dirpath, fn)],
                library_dirs=library_dirs,
                libraries=libraries,
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
    version=VERSION,
    description=(
        "hash, hmac, RSA, ECC, X.509, TLS, DTLS, handshakes, and secrets "
        "with an mbed TLS back end"
    ),
    long_description=readme(),
    long_description_content_type="text/x-rst",
    author="Mathias Laurin",
    author_email="Mathias.Laurin@github.com",
    license="MIT License",
    url="https://github.com/Synss/python-mbedtls",
    download_url=DOWNLOAD_URL,
    ext_modules=list(extensions(COVERAGE)),
    options=options(COVERAGE),
    package_data={"mbedtls": ["py.typed", "**.pyi"]},
    package_dir={"": "src"},
    packages=find_packages("src"),
    setup_requires=setup_requires,
    install_requires=install_requires,
    tests_require=tests_require,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ],
)
