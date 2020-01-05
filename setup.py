import ctypes
import os
import sys
from setuptools import setup, Extension, find_packages

version = "1.0.0"
mbedtls_version = "2.16.3"
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
    "setuptools>=18.0",
    # Cython 0.28 handles const memoryviews.
    "cython>=0.28.0",
]
install_requires = ["certifi"]
if sys.version_info < (3,):
    install_requires.extend(["contextlib2", "enum34", "pathlib2"])
tests_require = ["readme_renderer"]
if sys.version_info < (3,):
    tests_require.extend(["contextlib2"])


def mbedtls_version(lib):
    null = b"\0"
    output = 18 * null
    output_p = ctypes.c_char_p(output)
    lib.mbedtls_version_get_string_full(output_p)
    return output.strip(null).decode("ascii")


def mbedtls_version_info(lib):
    version = lib.mbedtls_version_get_number()
    return tuple(version >> shift & 0xFF for shift in (24, 16, 8))


def load_mbedtls():
    if sys.platform.startswith("linux"):
        name = "libmbedtls.so"
    elif sys.platform == "darwin":
        name = "libmbedtls.dylib"
    else:
        return None
    return ctypes.cdll.LoadLibrary(name)


def check_mbedtls_support(version, url):
    try:
        lib = load_mbedtls()
        if not lib:
            # I do not know the other platforms, so let us
            # skip the check for now.
            return
        sys.stdout.write(
            "  mbedtls version: {!s}{sep}".format(
                mbedtls_version(lib), sep=os.linesep
            )
        )
    except OSError:
        lib = None
        sys.stderr.write(
            "  mbedtls not found: could not load shared library{sep}".format(
                sep=os.linesep
            )
        )
    if lib is None or mbedtls_version_info(lib) < version[:2]:
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
                library_dirs=[
                    os.environ.get("LD_LIBRARY_PATH", ""),
                    os.environ.get("DYLD_LIBRARY_PATH", ""),
                ],
                libraries=["mbedcrypto", "mbedtls", "mbedx509"],
                define_macros=[
                    ("CYTHON_TRACE", "1"),
                    ("CYTHON_TRACE_NOGIL", "1"),
                ]
                if coverage
                else [],
            )
            extension.cython_directives = {"language_level": 3}
            if coverage:
                extension.cython_directives["linetrace"] = True
            yield extension


def options(coverage=False):
    if coverage:
        return {}
    else:
        return {
            "build": {"build_base": "build-%i.%i.%i" % sys.version_info[:3]},
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
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ],
)
