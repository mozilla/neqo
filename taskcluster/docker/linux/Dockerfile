FROM alpine:latest@sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0
LABEL maintainer="Mozilla Release Engineering <release+docker@mozilla.com>"

# Add worker user
RUN mkdir /builds && \
    adduser -h /builds/worker -s /bin/ash -D worker && \
    mkdir /builds/worker/artifacts && \
    chown worker:worker /builds/worker/artifacts

# Update repositories
RUN apk update

# Setup Python
RUN apk add --no-cache python3 py3-pip && \
    python3 -m pip install --no-cache --upgrade --break-system-packages pip setuptools

# Setup other dependencies
RUN apk add bash git

# %include-run-task

ENV SHELL=/bin/ash \
    HOME=/builds/worker \
    PATH=/builds/worker/.local/bin:$PATH

VOLUME /builds/worker/checkouts
VOLUME /builds/worker/.cache

# Set a default command useful for debugging
CMD ["/bin/ash"]
