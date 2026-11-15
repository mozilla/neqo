# How we would like patches made

## Size and scope of a fix

- Fix the root cause, minimally, where the input is first parsed or checked. Also fix defects in the
  code path the fix touches; name similar issues elsewhere in the report instead.
- Follow the spec (see `threat_model.md`), including SHOULDs. Raise the error it requires, reusing
  an existing error variant; never panic on peer data. Do not weaken assertions; handle the
  condition that trips them.
- Work with any RFC-compliant peer, any number of streams and every valid configuration, not only
  neqo and the defaults.
- No cost on the normal path, and no new dependencies unless unavoidable; say
  so if so.
- One root cause per patch.

## Code style

- Follow the surrounding code; reuse existing helpers and terminology. Stable Rust at the workspace
  `rust-version`.
- Fix lints by changing code, not with `#[expect]`.
- Default to no new comment; at most one line where the code cannot speak for itself. Keep existing
  comments.
- Format with `cargo +nightly fmt --all`; `bash .oss-scanner/ci.sh` must pass.

## Tests

- Add a regression test that fails without the fix and passes with it, in the existing test module
  for the area, using the helpers there and in `test-fixture`.
- Deterministic: simulated time, pinned randomness. Assert exact values derived from state or
  constants.

## Branch and commit message

- Against `main`. Conventional Commits subject, e.g. `fix(transport): validate HANDSHAKE_DONE on the
  client`, plus at most one short body sentence. No exploit details.
