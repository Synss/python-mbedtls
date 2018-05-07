import os
import sys
from setuptools import setup, Extension

version = "0.10.0"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = []
for dirpath, dirnames, filenames in os.walk("mbedtls"):
    for fn in filenames:
        root, ext = os.path.splitext(fn)
        if ext != ".pyx":
            continue
        mod = ".".join(dirpath.split(os.sep) + [root])
        extension = Extension(
            mod,
            [os.path.join(dirpath, fn)],
            libraries=["mbedcrypto", "mbedtls", "mbedx509"],
            include_dirs=["."],
        )
        extensions.append(extension)


setup_requires = [
    # Setuptools 18.0 properly handles Cython extensions.
    "setuptools>=18.0",
    # Cython 0.28 handles const memoryviews.
    "cython>=0.28.0",
]
if sys.version_info < (2, ):
    setup_requires.append("pathlib2")


def readme():
    with open("README.rst") as f:
        return f.read()


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
    ext_modules=extensions,
    options={
        "build": {"build_base": "build-%i.%i.%i" % sys.version_info[:3]},
        "build_ext": {"cython_c_in_temp": True},
    },
    packages=["mbedtls", "mbedtls.cipher"],
    setup_requires=setup_requires,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ]
)
