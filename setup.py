import os
import sys
from setuptools import setup, Extension, find_packages

version = "0.16.0"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


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
install_requires = [
    "certifi",
]
if sys.version_info < (3, ):
    install_requires.extend([
        "contextlib2",
        "enum34",
        "pathlib2",
    ])
tests_require = [
    "readme_renderer",
]
if sys.version_info < (3, ):
    tests_require.extend([
        "contextlib2",
    ])


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
                    ("CYTHON_TRACE_NOGIL", "1")
                ] if coverage else [],
            )
            extension.cython_directives = {"language_level": 2}
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


setup(
    name="python-mbedtls",
    version=version,
    description="hash, hmac, RSA, and X.509 with an mbed TLS back end",
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
        "Development Status :: 4 - Beta",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ]
)
