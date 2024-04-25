FROM martenseemann/quic-network-simulator-endpoint@sha256:12596544531465e77bdede50dd1e85b2c46c00f1634b3445eed277ca177666db AS buildimage

RUN apt-get install -y --no-install-recommends \
    curl git mercurial coreutils \
    build-essential libclang-dev lld \
    gyp ninja-build zlib1g-dev python \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=stable

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

ADD --checksum=sha256:a3d541a5484c8fa2f1c21478a6f6c505a778d473c21d60a18a4df5185d320ef8 \
    https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init x86_64_rustup

ADD --checksum=sha256:76cd420cb8a82e540025c5f97bda3c65ceb0b0661d5843e6ef177479813b0367 \
    https://static.rust-lang.org/rustup/dist/aarch64-unknown-linux-gnu/rustup-init aarch64_rustup

RUN mv $(uname -m)_rustup rustup-init && \
    chmod +x rustup-init && \
    ./rustup-init -y -q --no-modify-path --profile minimal --default-toolchain $RUST_VERSION

ENV NSS_DIR=/nss \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

RUN set -eux; \
    git clone --depth=1 https://github.com/nss-dev/nspr "$NSPR_DIR"; \
    git clone --depth=1 https://github.com/nss-dev/nss "$NSS_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

ADD . /neqo

RUN set -eux; \
    cd /neqo; \
    RUSTFLAGS="-C link-arg=-fuse-ld=lld" cargo build --release \
    --bin neqo-client --bin neqo-server

# Copy only binaries to the final image to keep it small.

FROM martenseemann/quic-network-simulator-endpoint@sha256:12596544531465e77bdede50dd1e85b2c46c00f1634b3445eed277ca177666db

ENV LD_LIBRARY_PATH=/neqo/lib
COPY --from=buildimage /neqo/target/release/neqo-client /neqo/target/release/neqo-server /neqo/bin/
COPY --from=buildimage /dist/Release/lib/*.so /neqo/lib/
COPY --from=buildimage /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/

COPY qns/interop.sh /neqo/
RUN chmod +x /neqo/interop.sh
ENTRYPOINT [ "/neqo/interop.sh" ]
