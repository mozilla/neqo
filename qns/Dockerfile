FROM martenseemann/quic-network-simulator-endpoint:latest AS buildimage

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential lld \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=stable

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- -y -q --no-modify-path --profile minimal --default-toolchain $RUST_VERSION

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
