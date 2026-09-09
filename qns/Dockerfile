FROM lukemathwalker/cargo-chef@sha256:d21902576546863995017609e991178939e6f151f6b35fb00f3c0fa97a616ef5 AS chef

WORKDIR /app

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Emit the NSS version and release tarball checksum pinned by nss-rs.
RUN apt-get update && apt-get install -y --no-install-recommends jq \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/* \
    && cargo metadata --format-version=1 -q \
        | jq -r '.packages[] | select(.name=="nss-rs") | .metadata.nss \
                 | "NSS_VERSION=" + .["min-version"], "NSS_SHA256=" + .sha256' > nss.env

FROM chef AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev gyp ninja-build python-is-python3 \
    && apt-get autoremove -y && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# We unfortunately need to build NSS from source, because the Debian package is
# not compiled with support for SSLKEYLOGFILE.
# See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842292
# Version and checksum sourced from the nss-rs dependency's [package.metadata.nss].
ENV NSS_DIR=/nss \
    NSS_TARGET=Release \
    NSS_PREBUILT=1 \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib

COPY --from=planner /app/nss.env /tmp/nss.env
RUN set -eux; \
    . /tmp/nss.env; \
    NSS_TAG=$(echo "$NSS_VERSION" | tr '.' '_'); \
    RELEASE_DIR="https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_TAG}_RTM/src"; \
    FILENAME=$(curl -fsSL "$RELEASE_DIR/SHA256SUMS" | grep -F "$NSS_SHA256 " | awk '{print $2}' | sed 's/^\*//'); \
    case "$FILENAME" in \
      nss-*-with-nspr-*.tar.gz) ;; \
      *) echo "No with-nspr artifact in NSS_${NSS_TAG}_RTM matches sha256 $NSS_SHA256" >&2; exit 1 ;; \
    esac; \
    curl -fL -o /tmp/nss.tar.gz "$RELEASE_DIR/$FILENAME"; \
    echo "$NSS_SHA256  /tmp/nss.tar.gz" | sha256sum -c; \
    tar xzf /tmp/nss.tar.gz --strip-components=1 -C /; \
    rm /tmp/nss.tar.gz;
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
