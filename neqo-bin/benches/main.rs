// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(clippy::unwrap_used, reason = "OK in a bench.")]

use std::{env, hint::black_box, net::SocketAddr, path::PathBuf, str::FromStr as _};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use neqo_bin::{client, server};
use tokio::runtime::Builder;

struct Benchmark {
    name: String,
    num_requests: usize,
    upload_size: usize,
    download_size: usize,
}

fn transfer(c: &mut Criterion) {
    neqo_crypto::init_db(PathBuf::from_str("../test-fixture/db").unwrap()).unwrap();

    let mtu = env::var("MTU").map_or_else(|_| String::new(), |mtu| format!("/mtu-{mtu}"));
    for Benchmark {
        name,
        num_requests,
        upload_size,
        download_size,
    } in [
        Benchmark {
            name: format!("1-conn/1-100mb-resp{mtu} (aka. Download)"),
            num_requests: 1,
            upload_size: 0,
            download_size: 100 * 1024 * 1024,
        },
        Benchmark {
            name: format!("1-conn/10_000-parallel-1b-resp{mtu} (aka. RPS)"),
            num_requests: 10_000,
            upload_size: 0,
            download_size: 1,
        },
        Benchmark {
            name: format!("1-conn/1-1b-resp{mtu} (aka. HPS)"),
            num_requests: 1,
            upload_size: 0,
            download_size: 1,
        },
        Benchmark {
            name: format!("1-conn/1-100mb-req{mtu} (aka. Upload)"),
            num_requests: 1,
            upload_size: 100 * 1024 * 1024,
            download_size: 0,
        },
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(if num_requests == 1 {
            Throughput::Bytes((upload_size + download_size) as u64)
        } else {
            Throughput::Elements(num_requests as u64)
        });
        group.bench_function("client", |b| {
            b.to_async(Builder::new_current_thread().enable_all().build().unwrap())
                .iter_batched(
                    || {
                        let (server_handle, server_addr) = spawn_server();
                        let client = client::client(client::Args::new(
                            Some(server_addr),
                            num_requests,
                            upload_size,
                            download_size,
                        ));
                        (server_handle, client)
                    },
                    |(server_handle, client)| {
                        black_box(async move {
                            client.await.unwrap();
                            // Tell server to shut down.
                            server_handle.send(()).unwrap();
                        })
                    },
                    BatchSize::PerIteration,
                );
        });
        group.finish();
    }
}

fn spawn_server() -> (tokio::sync::oneshot::Sender<()>, SocketAddr) {
    let (done_sender, mut done_receiver) = tokio::sync::oneshot::channel();
    let (addr_sender, addr_receiver) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();

        let mut args = server::Args::default();
        args.set_hosts(vec!["[::]:0".to_string()]);
        // `server.run` calls tokio's `UdpSocket::from_std` which requires a
        // Tokio runtime. Ensure one is available by running it in
        // `runtime.block_on`.
        let (server, local_addrs) = runtime.block_on(async { server::run(args).unwrap() });

        addr_sender
            .send(local_addrs.into_iter().find(SocketAddr::is_ipv6).unwrap())
            .unwrap();

        runtime.block_on(async {
            let mut server = Box::pin(server);
            tokio::select! {
                _ = &mut done_receiver => {}
                res = &mut server  => panic!("expect server not to terminate: {res:?}"),
            };
        });
    });
    (done_sender, addr_receiver.recv().unwrap())
}

criterion_group!(benches, transfer);
criterion_main!(benches);
