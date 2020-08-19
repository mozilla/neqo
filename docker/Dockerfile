# This image is used for running CI tests.
# The image is not built unless the `docker` branch is updated.
# Push to `docker` to trigger a build:
#  $ git push origin main:docker

FROM ubuntu:20.04
LABEL maintainer="Martin Thomson <mt@lowentropy.net>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates coreutils curl git make mercurial ssh \
    build-essential clang llvm libclang-dev lld \
    gyp ninja-build pkg-config zlib1g-dev sudo \
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.43.0

RUN set -eux; \
    curl -sSLf "https://static.rust-lang.org/rustup/archive/1.20.2/x86_64-unknown-linux-gnu/rustup-init" -o rustup-init; \
    echo 'e68f193542c68ce83c449809d2cad262cc2bbb99640eb47c58fc1dc58cc30add *rustup-init' | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y -q --no-modify-path --profile minimal --component rustfmt --component clippy --default-toolchain "$RUST_VERSION"; \
    rm -f rustup-init; \
    chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

ENV USER neqo
ENV LOGNAME $USER
ENV HOSTNAME $USER
ENV HOME /home/$USER
ENV SHELL /bin/bash

RUN useradd -d "$HOME" -s "$SHELL" -m "$USER"
RUN echo "$USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR $HOME
USER $USER

ENV NSS_DIR=$HOME/nss \
    NSPR_DIR=$HOME/nspr \
    LD_LIBRARY_PATH=$HOME/dist/Debug/lib \
    RUSTFLAGS="-C link-arg=-fuse-ld=lld"

RUN set -eux; \
    hg clone -u c7a1c91cd9be https://hg.mozilla.org/projects/nss "$NSS_DIR"; \
    hg clone -u NSPR_4_25_RTM https://hg.mozilla.org/projects/nspr "$NSPR_DIR"
