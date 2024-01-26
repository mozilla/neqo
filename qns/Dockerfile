FROM martenseemann/quic-network-simulator-endpoint:latest AS buildimage

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git mercurial \
    build-essential libclang-dev lld \
    gyp ninja-build zlib1g-dev python \
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=stable

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    curl https://sh.rustup.rs -sSf | \
    sh -s -- -y -q --no-modify-path --profile minimal --default-toolchain $RUST_VERSION

ENV NSS_DIR=/nss \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

RUN set -eux; \
    git clone --depth=1 https://github.com/nss-dev/nss "$NSS_DIR"; \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

ADD . /neqo

RUN set -eux; \
    cd /neqo; \
    RUSTFLAGS="-g -C link-arg=-fuse-ld=lld" cargo build --release \
      --bin neqo-client --bin neqo-server

# Copy only binaries to the final image to keep it small.

FROM martenseemann/quic-network-simulator-endpoint:latest

ENV LD_LIBRARY_PATH=/neqo/lib
COPY --from=buildimage /neqo/target/release/neqo-client /neqo/target/release/neqo-server /neqo/bin/
COPY --from=buildimage /dist/Release/lib/*.so /neqo/lib/
COPY --from=buildimage /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/

COPY qns/interop.sh /neqo/
RUN chmod +x /neqo/interop.sh
ENTRYPOINT [ "/neqo/interop.sh" ]
