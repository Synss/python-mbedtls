from setuptools import setup, Extension


version = "0.1"
download_url = "https://github.com/Synss/python-mbedtls/tarball/%s" % version


extensions = [
    Extension("mbedtls.cipher", ["mbedtls/cipher.pyx"],
              libraries=["mbedtls"],
              ),
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
