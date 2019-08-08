# Neqo, an Implementation of QUIC written in Rust

To run test http 0.9 programs (neqo-client and neqo-server):

* `cargo build`
* `./target/debug/neqo-server 12345 -k key --db ./test-fixture/db`
* `./target/debug/neqo-client http://127.0.0.1:12345/ -o --db ./test-fixture/db`

To run test http 3 programs (neqo-client and neqo-http3-server):

* `cargo build`
* `./target/debug/neqo-http3-server [::]:12345 --db ./test-fixture/db`
* `./target/debug/neqo-client http://127.0.0.1:12345/ --db ./test-fixture/db`

