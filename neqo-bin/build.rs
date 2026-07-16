use cfg_aliases::cfg_aliases;

#[allow(
    clippy::allow_attributes,
    semicolon_in_expressions_from_macros,
    reason = "TODO: Remove once https://github.com/katharostech/cfg_aliases/pull/15 releases."
)]
fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Platforms
        apple: {
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos"
            )
        },
    }
}
