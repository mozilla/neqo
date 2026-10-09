# Image for https://github.com/anthropics/oss-scanner. Everything the scanner may need must be fetched and built here;
# the scan itself runs offline.
FROM rust:1-trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev gyp ninja-build python-is-python3 jq llvm \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy \
    && rustup toolchain install nightly --profile minimal --component rustfmt \
    && cargo install --locked cargo-fuzz

COPY . /src
WORKDIR /src
# Image layers keep whole-second mtimes only; match that so cargo's prebuilt fingerprints stay fresh.
RUN find /src -exec touch -h -d "@$(date +%s)" {} +

# Build NSS from the release tarball pinned by nss-rs, so nss-rs never needs to fetch it.
ENV NSS_DIR=/nss \
    NSS_TARGET=Release \
    NSS_PREBUILT=1 \
    NSPR_DIR=/nspr \
    LD_LIBRARY_PATH=/dist/Release/lib
RUN set -eux; \
    eval "$(cargo metadata --locked --format-version=1 -q \
        | jq -r '.packages[] | select(.name=="nss-rs") | .metadata.nss \
                 | "NSS_VERSION=" + .["min-version"], "NSS_SHA256=" + .sha256')"; \
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
    rm /tmp/nss.tar.gz; \
    "$NSS_DIR"/build.sh --static -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 -Ddisable_ckbi=1 -Ddisable_fips=1 -o

ENV LSAN_OPTIONS=suppressions=/src/.oss-scanner/lsan.supp

# Fetch every dependency and prebuild the binaries, tests and (ASan) fuzz targets, because the agent has only 2 CPUs.
ENV CARGO_NET_OFFLINE=true
RUN CARGO_NET_OFFLINE=false cargo fetch --locked \
    && cargo build --locked --workspace --all-targets \
    && cargo test --locked --workspace --exclude mtu --no-run
# LTO is off because of https://github.com/rust-fuzz/cargo-fuzz/issues/384.
RUN CARGO_PROFILE_RELEASE_LTO=false cargo +nightly fuzz build --debug-assertions

# Check the image works, but don't fail the build on test failures. mtu tests need GitHub Actions.
RUN timeout 1200 cargo test --locked --workspace --exclude mtu \
    || echo "WARNING: cargo test reported failures"
