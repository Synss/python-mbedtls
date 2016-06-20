import os
from setuptools import setup, Extension


version = "0.6"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = []
for dirpath, dirnames, filenames in os.walk("mbedtls"):
    for fn in filenames:
        root, ext = os.path.splitext(fn)
        if ext != ".c":
            continue
        mod = ".".join(dirpath.split(os.sep) + [root])
        extensions.append(Extension(
            mod, [os.path.join(dirpath, fn)],
            libraries=["mbedtls"], include_dirs=["."]))


setup(
    name="python-mbedtls",
    version=version,
    description="mbed TLS (PolarSSL) wrapper",
    author="Mathias Laurin",
    author_email="Mathias.Laurin@users.sf.net",
    license="MIT License",
    url="https://synss.github.io/python-mbedtls",
    download_url=download_url,
    ext_modules=extensions,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Cython",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ]
)
