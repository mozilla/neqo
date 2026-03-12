// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{env, fs::File, io::Write, path::Path};

use sha1::{Digest as _, Sha1};

/// Write a data item `data` for the fuzzing target `target` to the fuzzing corpus. The caller needs
/// to make sure that `target` is the correct fuzzing target name for the data written.
///
/// The corpus directory can be specified via the `NEQO_CORPUS` environment variable.
/// If not set, defaults to `../fuzz/corpus`.
///
/// # Panics
///
/// Panics if the corpus directory does not exist or if the corpus item cannot be written.
pub fn write_item_to_fuzzing_corpus(target: &str, data: &[u8]) {
    // This bakes in the assumption that we're executing in the root of the neqo workspace.
    // Unfortunately, `cargo fuzz` doesn't provide a way to learn the location of the corpus
    // directory.
    let corpus =
        Path::new(&env::var("NEQO_CORPUS").unwrap_or_else(|_| "../fuzz/corpus".to_string()))
            .join(target);
    if !corpus.exists() {
        std::fs::create_dir_all(&corpus).expect("failed to create corpus directory");
    }

    // Hash the data using SHA1 (like LLVM) to get a unique name for the corpus item.
    let mut hasher = Sha1::new();
    hasher.update(data);
    let item_name = hex::encode(hasher.finalize());
    let item_path = corpus.join(item_name);
    if item_path.exists() {
        // Don't overwrite existing corpus items.
        return;
    }

    // Write the data to the corpus item.
    let mut file = File::create(item_path).expect("failed to create corpus item");
    Write::write_all(&mut file, data).expect("failed to write to corpus item");
}
