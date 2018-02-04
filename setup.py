import os
from setuptools import setup, Extension

version = "0.7"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = []
for dirpath, dirnames, filenames in os.walk("mbedtls"):
    for fn in filenames:
        root, ext = os.path.splitext(fn)
        if ext != ".pyx":
            continue
        mod = ".".join(dirpath.split(os.sep) + [root])
        extensions.append(Extension(
            mod,
            [os.path.join(dirpath, fn)],
            libraries=["mbedtls"],
        ))


def readme():
    with open("README.rst") as f:
        return f.read()


setup(
    name="python-mbedtls",
    version=version,
    description="mbed TLS (PolarSSL) wrapper",
    long_description=readme(),
    author="Mathias Laurin",
    author_email="Mathias.Laurin@users.sf.net",
    license="MIT License",
    url="https://github.com/Synss/python-mbedtls",
    download_url=download_url,
    ext_modules=extensions,
    setup_requires=[
        # Setuptools 18.0 properly handles Cython extensions.
        "setuptools>=18.0",
        "cython",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ]
)
