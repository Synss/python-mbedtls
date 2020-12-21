ARG ARCH

FROM quay.io/pypa/manylinux2010_${ARCH}:latest AS base

FROM base AS builder
WORKDIR /home/builder
ARG  MBEDTLS
ARG  TAGS
RUN  yum -y update \
  && yum -y -q install cmake \
  && yum clean all \
  && cmake --version
RUN  ls /opt/python/
COPY ./scripts/download-mbedtls.sh ./scripts/install-mbedtls.sh ./scripts/
RUN  ./scripts/download-mbedtls.sh "${MBEDTLS:?}" /usr/local/src \
  && ./scripts/install-mbedtls.sh /usr/local/src /usr/local \
  && cp /usr/local/src/LICENSE LICENSE.mbedtls \
  && rm -r /usr/local/src
COPY ./setup.py ./README.rst ./
COPY ./src/ ./src/
COPY ./scripts/build-wheel.sh ./scripts/
RUN  for PYTHON in `echo "${TAGS:?}"`; do \
     ./scripts/build-wheel.sh /opt/python/${PYTHON}/bin/python linux; \
     done

FROM base
WORKDIR /root
COPY ./scripts/ ./scripts/
COPY ./README.rst ./
COPY --from=builder /home/builder/wheelhouse ./wheelhouse
COPY ./requirements/ ./requirements/
COPY ./tests/ ./tests/
RUN  ls ./
