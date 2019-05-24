#[derive(Default, Debug)]
/// Connection statistics
pub struct Stats {
    /// Total packets received
    pub packets_rx: u64,
    /// Total packets sent
    pub packets_tx: u64,
    /// Duplicate packets received
    pub dups_rx: u64,
}
