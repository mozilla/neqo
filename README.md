# Neqo

To run test http 0.9 programs (neqo-client and neqo-server):

* `cargo build`
* `./target/debug/neqo-server 12345 -k key --db ./neqo-crypto/db`
* `./target/debug/neqo-client http://127.0.0.1:12345/ -o --db ./neqo-crypto/db`

To run test http 3 programs (neqo-client and neqo-http3-server):

* `cargo build`
* `./target/debug/neqo-http3-server -p 12345 --db ./neqo-crypto/db`
* `./target/debug/neqo-client http://127.0.0.1:12345/ --db ./neqo-crypto/db`

