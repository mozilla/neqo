#!/bin/bash

/setup.sh

set -ex

export PATH="${PATH}:/neqo/bin"

[ -n "$TESTCASE" ]
[ -n "$QLOGDIR" ]

case "$ROLE" in
client)
  /wait-for-it.sh sim:57832 -s -t 30
  OPTIONS=(--cc cubic --qns-test "$TESTCASE" --qlog-dir "$QLOGDIR" --output-dir /downloads)
  if [ "$REQUESTS" ]; then
    read -ra URLS <<<"$REQUESTS"
    OPTIONS+=("${URLS[@]}")
  fi
  RUST_LOG=debug RUST_BACKTRACE=1 neqo-client "${OPTIONS[@]}" 2> >(tee -i -a "/logs/$ROLE.log" >&2)
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
  OPTIONS=(--cc cubic --qns-test "$TESTCASE" --qlog-dir "$QLOGDIR" -d "$DB" -k "$CERT")
  [ "$TESTCASE" = "connectionmigration" ] &&
    OPTIONS+=(--preferred-address-v4 server4:4443 --preferred-address-v6 server6:4443)
  RUST_LOG=debug RUST_BACKTRACE=1 neqo-server "${OPTIONS[@]}" '[::]:443' 2> >(tee -i -a "/logs/$ROLE.log" >&2)
  ;;

*)
  exit 1
  ;;
esac
