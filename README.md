# Neqo

To run test programs (neqo-client and neqo-server):

* `cargo build`
* `./target/debug/neqo-server 12345 -k key -d ./neqo-crypto/db`
* `./target/debug/neqo-client 127.0.0.1 12345 --db ./neqo-crypto/db`
