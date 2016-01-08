from setuptools import setup, Extension


version = "0.3"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = [
    Extension("mbedtls.exceptions", ["mbedtls/exceptions.pyx"]),
] + [
    Extension("mbedtls.cipher.%s" % name, ["mbedtls/cipher/%s.pyx" % name],
              libraries=["mbedtls"],
              include_dirs=["."],) for name in
    "_cipher __init__".split() +
    "AES ARC4 Blowfish Camellia DES DES3 DES3dbl".split()
] + [
    Extension("mbedtls.%s" % name, ["mbedtls/%s.pyx" % name],
              libraries=["mbedtls"],
              include_dirs=["."],)
    for name in "_md __init__ hash hmac".split()
]

setup_requires = ["cython"]


setup(
    name="python-mbedtls",
    version=version,
    description="mbed TLS (PolarSSL) wrapper",
    author="Mathias Laurin",
    author_email="Mathias.Laurin@users.sf.net",
    license="Apache 2.0 License",
    url="https://synss.github.io/python-mbedtls",
    download_url=download_url,
    ext_modules=extensions,
    setup_requires=setup_requires,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Cython",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Security :: Cryptography",
    ]
)
