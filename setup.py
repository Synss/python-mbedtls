from setuptools import setup, Extension
from Cython.Build import cythonize

setup(
    name="mbed TLS wrapper",
    ext_modules=cythonize([
        Extension("mbedtls.cipher", ["mbedtls/cipher.pyx"],
                  libraries=["mbedtls"]),
    ])
)
