// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{path::PathBuf, str::FromStr};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use tokio::runtime::Runtime;

struct Benchmark {
    name: String,
    requests: Vec<u64>,
    /// Download resources in series using separate connections.
    download_in_series: bool,
    sample_size: Option<usize>,
}

fn transfer(c: &mut Criterion) {
    neqo_common::log::init(Some(log::LevelFilter::Off));
    // TODO: Init log level here once https://github.com/mozilla/neqo/pull/1692 is merged.
    neqo_crypto::init_db(PathBuf::from_str("../test-fixture/db").unwrap());

    let done_sender = spawn_server();

    for Benchmark {
        name,
        requests,
        download_in_series,
        sample_size,
    } in [
        Benchmark {
            name: "1-conn/1-1gb-resp".to_string(),
            requests: vec![1024 * 1024 * 1024],
            download_in_series: false,
            sample_size: Some(10),
        },
        Benchmark {
            name: "1-conn/1-100mb-resp".to_string(),
            requests: vec![100 * 1024 * 1024],
            download_in_series: false,
            sample_size: None,
        },
        Benchmark {
            name: "1-conn/10_000-1b-seq-resp (aka. RPS)".to_string(),
            requests: vec![1; 10_000],
            download_in_series: false,
            sample_size: None,
        },
        Benchmark {
            name: "100-seq-conn/1-1b-resp (aka. HPS)".to_string(),
            requests: vec![1; 100],
            download_in_series: true,
            sample_size: None,
        },
    ] {
        let mut group = c.benchmark_group(name);
        group.throughput(if requests[0] > 1 {
            assert_eq!(requests.len(), 1);
            Throughput::Bytes(requests[0])
        } else {
            Throughput::Elements(requests.len() as u64)
        });
        if let Some(size) = sample_size {
            group.sample_size(size);
        }
        group.bench_function("client", |b| {
            b.to_async(Runtime::new().unwrap()).iter_batched(
                || {
                    neqo_bin::client::client(neqo_bin::client::Args::new(
                        &requests,
                        download_in_series,
                    ))
                },
                |client| async move {
                    client.await.unwrap();
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    }

    done_sender.send(()).unwrap();
}

fn spawn_server() -> tokio::sync::oneshot::Sender<()> {
    let (done_sender, mut done_receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        Runtime::new().unwrap().block_on(async {
            let mut server = Box::pin(neqo_bin::server::server(neqo_bin::server::Args::default()));
            tokio::select! {
                _ = &mut done_receiver => {}
                _ = &mut server  => {}
            }
        });
    });
    done_sender
}

criterion_group!(benches, transfer);
criterion_main!(benches);
