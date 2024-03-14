FROM martenseemann/quic-network-simulator-endpoint:latest AS buildimage

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential libclang-dev pkg-config \
    build-essential procps curl file git \
    && apt-get remove -y pkg-config \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=stable

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- -y -q --no-modify-path --profile minimal --default-toolchain $RUST_VERSION

# Pull in a newer version of NSS with Homebrew. Note this only works on Intel platforms.
# Once martenseemann/quic-network-simulator-endpoint uses an Ubuntu flavor with a new-enough
# NSS, we should remove this and install NSS from the package manager.
RUN useradd --create-home --shell /bin/bash --user-group linuxbrew \
    && echo 'linuxbrew ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers
USER linuxbrew
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
RUN /home/linuxbrew/.linuxbrew/bin/brew install nss pkg-config

ADD . /neqo

RUN set -eux; \
    cd /neqo; \
    cargo build --release --bin neqo-client --bin neqo-server

# Copy only binaries to the final image to keep it small.

FROM martenseemann/quic-network-simulator-endpoint:latest

# TODO: install NSS
COPY --from=buildimage /neqo/target/release/neqo-client /neqo/target/release/neqo-server /neqo/bin/

COPY qns/interop.sh /neqo/
RUN chmod +x /neqo/interop.sh
ENTRYPOINT [ "/neqo/interop.sh" ]
