# Build process for linux

## Table of contents

1. [System Details](#system-details)
2. [Installation Steps](#installation-steps)

## System Details

**Linux Kernel:** 4.15.0-101-generic  
**Ubuntu:** 18.04

```shell
rustup show
```

```output
Default host: x86_64-unknown-linux-gnu
rustup home:  /home/akshay/.rustup

installed toolchains
--------------------

stable-x86_64-unknown-linux-gnu
nightly-2020-04-22-x86_64-unknown-linux-gnu
nightly-x86_64-unknown-linux-gnu

installed targets for active toolchain
--------------------------------------

wasm32-unknown-unknown
x86_64-unknown-linux-gnu

active toolchain
----------------

stable-x86_64-unknown-linux-gnu (default)
rustc 1.41.0 (5e1a79984 2020-01-27)
```

```shell
rustup --version
```

```output
rustup 1.21.1 (7832b2ebe 2019-12-20)
```

```shell
rustc --version
```

```output
rustc 1.41.0 (5e1a79984 2020-01-27)
```

```shell
cargo --version
```

```output
cargo 1.41.0 (626f0f40e 2019-12-03)
```

```shell
rustfmt --version
```

```output
rustfmt 1.4.11-stable (1838235 2019-12-03)
```

```shell
cargo clippy --version
```

```output
clippy 0.0.212 (69f99e7 2019-12-14)
```

## Installation Steps

1. Install dependencies.

```shell
sudo apt-get update
```

```shell
sudo apt-get install -y --no-install-recommends \
ca-certificates coreutils curl git make mercurial ssh \
build-essential clang llvm libclang-dev gyp ninja-build \
pkg-config zlib1g-dev sudo
```

2. Remove orphaned packages and clear local repository (optional)

```shell
sudo apt-get autoremove -y && sudo apt-get clean -y
```

3. Install rust. Follow the steps from [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

4. Export following path variables. `$HOME` is your home directory which is usually `/home/{username}`. `LD_LIBRARY_PATH` will be `$NSS_DIR/../dist/Debug/lib`

```shell
export NSS_DIR=$HOME/nss
export NSPR_DIR=$HOME/nspr
export LD_LIBRARY_PATH=$HOME/dist/Debug/lib
```

5. Clone **NSS** and **NSPR**

```shell
hg clone -u c7a1c91cd9be https://hg.mozilla.org/projects/nss "$NSS_DIR"
hg clone -u NSPR_4_25_RTM https://hg.mozilla.org/projects/nspr "$NSPR_DIR"
```

6. Build **NSS**

```shell
cd $NSS_DIR
./build.sh --static -Ddisable_tests=1
```

7. Navigate to your workspace and checkout **Neqo**

```shell
git clone https://github.com/mozilla/neqo.git
```

8. Build neqo and run all tests

```shell
cd neqo
cargo build -v --all-targets --tests
cargo test -v
```

9. Run HTTP/3 programs

```shell
#Start server
./target/debug/neqo-http3-server [::]:12345 --db ./test-fixture/db
#Run Client (In seperate shell. Will require LD_LIBRARY_PATH to be exported)
./target/debug/neqo-client http://127.0.0.1:12345/
```
