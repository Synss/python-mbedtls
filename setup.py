from setuptools import setup, Extension


version = "0.4"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = [
    Extension("mbedtls.exceptions", ["mbedtls/exceptions.c"]),
] + [
    Extension("mbedtls.random", ["mbedtls/random.c"],
              libraries=["mbedtls"],
              include_dirs=["."],)
] + [
    Extension("mbedtls.cipher.%s" % name, ["mbedtls/cipher/%s.c" % name],
              libraries=["mbedtls"],
              include_dirs=["."],) for name in
    "_cipher __init__".split() +
    "AES ARC4 Blowfish Camellia DES DES3 DES3dbl".split()
] + [
    Extension("mbedtls.pk.%s" % name, ["mbedtls/pk/%s.c" % name],
              libraries=["mbedtls"],
              include_dirs=["."],) for name in
    "_pk __init__ RSA".split()
] + [
    Extension("mbedtls.%s" % name, ["mbedtls/%s.c" % name],
              libraries=["mbedtls"],
              include_dirs=["."],)
    for name in "_md __init__ hash hmac".split()
]

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
