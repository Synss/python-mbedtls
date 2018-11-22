ARG ARCH=x86_64
FROM quay.io/pypa/manylinux1_${ARCH}
WORKDIR /home/docker
ENV PATH "/opt/python/cp36-cp36m/bin:${PATH}"
RUN yum -y update \
    && yum -yq install cmake \
    && yum clean all
