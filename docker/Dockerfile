FROM ubuntu:18.04
LABEL maintainer="Martin Thomson <mt@lowentropy.net>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates coreutils curl git make mercurial ssh \
    build-essential libc6-dev libc++-dev gyp ninja-build pkg-config zlib1g-dev \
    libclang1 \
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=nightly-2019-03-23

RUN set -eux; \
    curl -sSLf "https://static.rust-lang.org/rustup/archive/1.16.0/x86_64-unknown-linux-gnu/rustup-init" -o rustup-init; \
    echo '2d4ddf4e53915a23dda722608ed24e5c3f29ea1688da55aa4e98765fc6223f71 *rustup-init' | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain "$RUST_VERSION"; \
    rm -f rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup component add rustfmt; \
    rustup --version; \
    cargo --version; \
    rustc --version; \
    rustfmt --version

ENV USER neqo
ENV LOGNAME $USER
ENV HOSTNAME $USER
ENV HOME /home/$USER
ENV SHELL /bin/bash

RUN useradd -d "$HOME" -s "$SHELL" -m "$USER"
WORKDIR $HOME
USER $USER
