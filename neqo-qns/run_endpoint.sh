#!/bin/bash

# Set up the routing needed for the simulation.
./setup.sh

cd neqo

CLIENT_PARAMS="--qns-mode --output-dir /downloads"
SERVER_PARAMS="--qns-mode 0.0.0.0:443"

if [ "$ROLE" == "client" ]; then
    echo "Starting Neqo client ..."
    echo "CLIENT_PARAMS:" $CLIENT_PARAMS
    echo "REQUESTS:" $REQUESTS
    sleep 5
    RUST_LOG=debug RUST_BACKTRACE=1 ./target/neqo-client $CLIENT_PARAMS $REQUESTS
elif [ "$ROLE" == "server" ]; then
    RUST_LOG=info RUST_BACKTRACE=1 ./target/neqo-http3-server $SERVER_PARAMS
fi
