FROM lukemathwalker/cargo-chef@sha256:9e564338159930326c71b6c3df9ed5e5b60b0437b84861c6bb6767b1964a0fd4 AS chef

WORKDIR /app

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev gyp ninja-build python-is-python3 \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# We unfortunately need to build NSS from source, because the Debian package is
# not compiled with support for SSLKEYLOGFILE.
# See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842292
# When NSPR and NSS versions are bumped, make sure to also update them in
# .github/actions/nss/action.yml.
ENV NSS_DIR=/nss \
    NSS_TARGET=Release \
    NSS_PREBUILT=1 \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib \
    NSPR_VERSION=4.38.2 \
    NSS_VERSION=3.119.1

RUN set -eux; \
    mkdir -p "$NSPR_DIR" "$NSS_DIR"; \
    curl -L "https://ftp.mozilla.org/pub/nspr/releases/v$NSPR_VERSION/src/nspr-$NSPR_VERSION.tar.gz" | tar xz --strip-components=2 -C "$NSPR_DIR"; \
    NSS_TAG=$(echo $NSS_VERSION | tr '.' '_'); \
    curl -L "https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_TAG}_RTM/src/nss-${NSS_TAG}.tar.gz" | tar xz --strip-components=2 -C "$NSS_DIR";

RUN "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 -Ddisable_ckbi=1 -Ddisable_fips=1 -o

COPY --from=planner /app/recipe.json recipe.json
# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
ADD . /neqo
RUN set -eux; \
    cd /neqo; \
    CARGO_PROFILE_RELEASE_DEBUG=true cargo build --locked --release --bin neqo-client --bin neqo-server

# Copy only binaries to the final image to keep it small.

FROM martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a

ENV LD_LIBRARY_PATH=/neqo/lib
COPY --from=builder /neqo/target/release/neqo-client /neqo/target/release/neqo-server /neqo/bin/
COPY --from=builder /dist/Release/lib/*.so /neqo/lib/
COPY --from=builder /dist/Release/bin/certutil /dist/Release/bin/pk12util /neqo/bin/

COPY qns/interop.sh /neqo/
RUN chmod +x /neqo/interop.sh
ENTRYPOINT [ "/neqo/interop.sh" ]
