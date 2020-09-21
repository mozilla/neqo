FROM martenseemann/quic-network-simulator-endpoint:latest AS buildimage

# Which branch to build from.
ARG NEQO_BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates coreutils curl git make mercurial ssh \
    build-essential clang llvm libclang-dev lld \
    gyp ninja-build pkg-config zlib1g-dev python \
 && apt-get autoremove -y && apt-get clean -y \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.45.2

RUN set -eux; \
    curl -sSLf "https://static.rust-lang.org/rustup/archive/1.22.1/x86_64-unknown-linux-gnu/rustup-init" -o rustup-init; \
    echo '49c96f3f74be82f4752b8bffcf81961dea5e6e94ce1ccba94435f12e871c3bdb *rustup-init' | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y -q --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"; \
    rm -f rustup-init; \
    chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"

ENV NSS_DIR=/nss \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

RUN set -eux; \
    hg clone https://hg.mozilla.org/projects/nss "$NSS_DIR"; \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

# Copy the .git directory from the local clone so that it is possible to create
# an image that includes local updates.
RUN mkdir -p /neqo-reference
ADD . /neqo-reference
RUN if [ -d /neqo-reference/.git ]; then \
      source=/neqo-reference; \
    else \
      source=https://github.com/mozilla/neqo; \
    fi; \
    git clone --depth 1 --branch "$NEQO_BRANCH" "$source" /neqo; \
    rm -rf /neqo-reference

RUN set -eux; \
    cd /neqo; \
    RUSTFLAGS="-g -C link-arg=-fuse-ld=lld" cargo build --release \
      --bin neqo-client --bin neqo-server; \
    cp target/release/neqo-client target; \
    cp target/release/neqo-server target; \
    rm -rf target/release

# Copy only binaries to the final image to keep it small.

FROM martenseemann/quic-network-simulator-endpoint:latest

ENV LD_LIBRARY_PATH=/neqo/lib
COPY --from=buildimage /neqo/target/neqo-client /neqo/target/neqo-server /neqo/bin/
COPY --from=buildimage /dist/Release/lib/*.so /neqo/lib/
COPY --from=buildimage /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/

COPY interop.sh /neqo/
RUN chmod +x /neqo/interop.sh
ENTRYPOINT [ "/neqo/interop.sh" ]
