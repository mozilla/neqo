// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Common configuration for Criterion benchmarks.

use std::time::Duration;

use criterion::Criterion;

/// Set to 1% to detect small but meaningful performance changes.
pub const NOISE_THRESHOLD: f64 = 0.01;

/// Sample size for fast benchmarks (pure compute).
const SAMPLE_SIZE_FAST: usize = 1000;

/// Sample size for walltime benchmarks.
const SAMPLE_SIZE_WALLTIME: usize = 500;

/// Creates a Criterion base configuration.
fn base_config(
    sample_size: usize,
    warm_up_time: Option<Duration>,
    measurement_time: Option<Duration>,
) -> Criterion {
    let mut c = Criterion::default()
        .sample_size(sample_size)
        .significance_level(0.01)
        .confidence_level(0.99);
    if let Some(dur) = warm_up_time {
        c = c.warm_up_time(dur);
    }
    if let Some(dur) = measurement_time {
        c = c.measurement_time(dur);
    }
    c
}

/// Configuration for fast, pure-compute benchmarks.
#[must_use]
pub fn config_fast() -> Criterion {
    base_config(SAMPLE_SIZE_FAST, None, None)
}

/// Configuration for simulation benchmarks.
#[must_use]
pub fn config_simulation() -> Criterion {
    base_config(
        SAMPLE_SIZE_FAST,
        Some(Duration::from_secs(5)),
        Some(Duration::from_secs(30)),
    )
}

/// Configuration for walltime benchmarks.
#[must_use]
pub fn config_walltime() -> Criterion {
    base_config(
        SAMPLE_SIZE_WALLTIME,
        Some(Duration::from_secs(10)),
        Some(Duration::from_secs(60)),
    )
}
