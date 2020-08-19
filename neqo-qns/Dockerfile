FROM martenseemann/quic-network-simulator-endpoint:latest AS buildimage

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

ENV NSS_DIR=$HOME/nss \
    NSPR_DIR=$HOME/nspr \
    LD_LIBRARY_PATH=$HOME/dist/Debug/lib

RUN set -eux; \
    hg clone https://hg.mozilla.org/projects/nss "$NSS_DIR"; \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -o

RUN git clone --depth 1 https://github.com/mozilla/neqo $HOME/neqo

RUN set -eux; \
    cd $HOME/neqo; \
    RUSTFLAGS="-g -C link-arg=-fuse-ld=lld" cargo build --release; \
    cp target/debug/neqo-client target; \
    cp target/debug/neqo-http3-server target; \
    rm -rf target/debug

# Copy only binaries to the final image to keep it small

FROM martenseemann/quic-network-simulator-endpoint:latest

ENV LD_LIBRARY_PATH=/neqo/lib
COPY --from=buildimage $HOME/neqo/target /neqo/target
COPY --from=buildimage $HOME/neqo/test-fixture/db /neqo/test-fixture/db
COPY --from=buildimage $HOME/dist/Debug/lib/*.so /neqo/lib/

COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
