# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3 \
    python3-pip \
    git \
    wget \
    libtool \
    texinfo \
    unzip    

# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

# Install wolfSSL
RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip && \
    unzip v5.7.6-stable.zip && \
    rm -f v5.7.6-stable.zip

ENV WOLFSSL_PATH=/root/wolfssl-5.7.6-stable

# Install some Python packages for gen_decoder_secrets.py
RUN python3 -m pip install --break-system-packages cryptography

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

