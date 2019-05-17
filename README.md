# Neqo

To run test programs (neqo-client and neqo-server):

* `cargo build`
* `./target/debug/neqo-server 12345 -k key -db ./neqo-crypto/db`
* `./target/debug/neqo-client 127.0.0.1 12345 --db ./neqo-crypto/db`

or

* `cargo build`
* `./target/debug/neqo-http3-server -p 12345 --db ./neqo-crypto/db`
* `./target/debug/neqo-http3-client http://127.0.0.1:12345/ --db ./neqo-crypto/db`

