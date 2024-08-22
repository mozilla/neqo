#!/bin/bash

/setup.sh

set -ex

export PATH="${PATH}:/neqo/bin"

[ -n "$TESTCASE" ]
[ -n "$QLOGDIR" ]

if [[ "$TESTCASE" == blackhole ]] || [[ "$TESTCASE" == transfer ]]; then
  # These tests generate way too much output with a "debug" log level.
  LOG_LEVEL=info
else
  LOG_LEVEL=debug
fi

case "$ROLE" in
client)
  /wait-for-it.sh sim:57832 -s -t 30
  # shellcheck disable=SC2086
  RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=1 neqo-client --cc cubic --qns-test "$TESTCASE" \
    --qlog-dir "$QLOGDIR" --output-dir /downloads $REQUESTS 2> >(tee -i -a "/logs/$ROLE.log" >&2)
  ;;

server)
  DB=/neqo/db
  CERT=cert
  P12CERT=$(mktemp)
  mkdir -p "$DB"
  certutil -N -d "sql:$DB" --empty-password
  openssl pkcs12 -export -nodes -in /certs/cert.pem -inkey /certs/priv.key \
    -name "$CERT" -passout pass: -out "$P12CERT"
  pk12util -d "sql:$DB" -i "$P12CERT" -W ''
  certutil -L -d "sql:$DB" -n "$CERT"
  RUST_LOG=$LOG_LEVEL RUST_BACKTRACE=1 neqo-server --cc cubic --qns-test "$TESTCASE" \
    --qlog-dir "$QLOGDIR" -d "$DB" -k "$CERT" '[::]:443' 2> >(tee -i -a "/logs/$ROLE.log" >&2)
  ;;

*)
  exit 1
  ;;
esac
