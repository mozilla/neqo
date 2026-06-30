// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;

use neqo_common::qdebug;
use neqo_qpack as qpack;
use neqo_transport::ConnectionParameters;

const QPACK_MAX_TABLE_SIZE_DEFAULT: u64 = 65536;
const QPACK_TABLE_SIZE_LIMIT: u64 = (1 << 30) - 1;
const QPACK_MAX_BLOCKED_STREAMS_DEFAULT: u16 = 20;
const MAX_PUSH_STREAM_DEFAULT: u64 = 0;
const WEBTRANSPORT_DEFAULT: bool = false;
/// Do not support HTTP Extended CONNECT by default.
const CONNECT_DEFAULT: bool = false;
const HTTP3_DATAGRAM_DEFAULT: bool = true;
/// Default per-session WebTransport flow control limits advertised in SETTINGS.
/// 0 means "do not advertise this setting" (treat as unlimited by peer).
const WT_INITIAL_MAX_DATA_DEFAULT: u64 = 0;
const WT_INITIAL_MAX_STREAMS_UNI_DEFAULT: u64 = 0;
const WT_INITIAL_MAX_STREAMS_BIDI_DEFAULT: u64 = 0;

#[derive(Debug, Clone)]
pub struct Http3Parameters {
    conn_params: ConnectionParameters,
    qpack_settings: qpack::Settings,
    max_concurrent_push_streams: u64,
    webtransport: bool,
    /// Per-session initial max data advertised to peer (draft-ietf-webtrans-http3-15).
    /// 0 means do not advertise this setting (treat as unlimited by peer).
    wt_initial_max_data: u64,
    /// Per-session initial max unidirectional streams advertised to peer.
    /// 0 means do not advertise this setting.
    wt_initial_max_streams_uni: u64,
    /// Per-session initial max bidirectional streams advertised to peer.
    /// 0 means do not advertise this setting.
    wt_initial_max_streams_bidi: u64,
    /// HTTP Extended CONNECT
    connect: bool,
    http3_datagram: bool,
}

impl Default for Http3Parameters {
    fn default() -> Self {
        Self {
            conn_params: ConnectionParameters::default(),
            qpack_settings: qpack::Settings {
                max_table_size_encoder: QPACK_MAX_TABLE_SIZE_DEFAULT,
                max_table_size_decoder: QPACK_MAX_TABLE_SIZE_DEFAULT,
                max_blocked_streams: QPACK_MAX_BLOCKED_STREAMS_DEFAULT,
            },
            max_concurrent_push_streams: MAX_PUSH_STREAM_DEFAULT,
            webtransport: WEBTRANSPORT_DEFAULT,
            wt_initial_max_data: WT_INITIAL_MAX_DATA_DEFAULT,
            wt_initial_max_streams_uni: WT_INITIAL_MAX_STREAMS_UNI_DEFAULT,
            wt_initial_max_streams_bidi: WT_INITIAL_MAX_STREAMS_BIDI_DEFAULT,
            connect: CONNECT_DEFAULT,
            http3_datagram: HTTP3_DATAGRAM_DEFAULT,
        }
    }
}

impl Http3Parameters {
    #[must_use]
    pub const fn get_connection_parameters(&self) -> &ConnectionParameters {
        &self.conn_params
    }

    #[must_use]
    pub fn connection_parameters(mut self, conn_params: ConnectionParameters) -> Self {
        self.conn_params = conn_params;
        self
    }

    /// # Panics
    ///
    /// The table size must be smaller than 1 << 30 by the spec.
    #[must_use]
    pub fn max_table_size_encoder(mut self, mut max_table: u64) -> Self {
        assert!(max_table <= QPACK_TABLE_SIZE_LIMIT);
        max_table = min(max_table, QPACK_TABLE_SIZE_LIMIT);
        self.qpack_settings.max_table_size_encoder = max_table;
        self
    }

    /// # Panics
    ///
    /// The table size must be smaller than 1 << 30 by the spec.
    #[must_use]
    pub fn max_table_size_decoder(mut self, mut max_table: u64) -> Self {
        assert!(max_table <= QPACK_TABLE_SIZE_LIMIT);
        max_table = min(max_table, QPACK_TABLE_SIZE_LIMIT);
        self.qpack_settings.max_table_size_decoder = max_table;
        self
    }

    #[must_use]
    pub const fn get_max_table_size_decoder(&self) -> u64 {
        self.qpack_settings.max_table_size_decoder
    }

    #[must_use]
    pub const fn max_blocked_streams(mut self, max_blocked: u16) -> Self {
        self.qpack_settings.max_blocked_streams = max_blocked;
        self
    }

    #[must_use]
    pub const fn get_max_blocked_streams(&self) -> u16 {
        self.qpack_settings.max_blocked_streams
    }

    #[must_use]
    pub const fn get_qpack_settings(&self) -> &qpack::Settings {
        &self.qpack_settings
    }

    #[must_use]
    pub const fn max_concurrent_push_streams(mut self, max_push_streams: u64) -> Self {
        self.max_concurrent_push_streams = max_push_streams;
        self
    }

    #[must_use]
    pub const fn get_max_concurrent_push_streams(&self) -> u64 {
        self.max_concurrent_push_streams
    }

    #[must_use]
    pub const fn webtransport(mut self, webtransport: bool) -> Self {
        self.webtransport = webtransport;
        self
    }

    #[must_use]
    pub const fn get_webtransport(&self) -> bool {
        self.webtransport
    }

    #[must_use]
    pub const fn wt_initial_max_data(mut self, max_data: u64) -> Self {
        self.wt_initial_max_data = max_data;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_data(&self) -> u64 {
        self.wt_initial_max_data
    }

    #[must_use]
    pub const fn wt_initial_max_streams_uni(mut self, max_streams: u64) -> Self {
        self.wt_initial_max_streams_uni = max_streams;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_streams_uni(&self) -> u64 {
        self.wt_initial_max_streams_uni
    }

    #[must_use]
    pub const fn wt_initial_max_streams_bidi(mut self, max_streams: u64) -> Self {
        self.wt_initial_max_streams_bidi = max_streams;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_streams_bidi(&self) -> u64 {
        self.wt_initial_max_streams_bidi
    }

    /// Setter for HTTP Extended CONNECT support.
    #[must_use]
    pub const fn connect(mut self, connect: bool) -> Self {
        self.connect = connect;
        self
    }

    /// Getter for HTTP Extended CONNECT support.
    #[must_use]
    pub const fn get_connect(&self) -> bool {
        self.connect
    }

    #[must_use]
    pub const fn http3_datagram(mut self, http3_datagram: bool) -> Self {
        self.http3_datagram = http3_datagram;
        self
    }

    #[must_use]
    pub fn get_http3_datagram(&self) -> bool {
        if self.http3_datagram && self.conn_params.get_datagram_size() == 0 {
            qdebug!(
                "HTTP/3 setting SETTINGS_H3_DATAGRAM is enabled but QUIC transport parameter max_datagram_frame_size is 0. Datagrams will be sent via HTTP DATAGRAM Capsules."
            );
        }
        self.http3_datagram
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neqo_transport::ConnectionParameters;

    use crate::Http3Parameters;

    #[test]
    fn http3_datagram_with_capsules_only() {
        let params = Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(0))
            .http3_datagram(true);
        assert!(params.get_http3_datagram());
    }

    #[test]
    fn max_table_size_accepts_limit() {
        // QPACK spec limits table size to (1 << 30) - 1.
        let limit = (1 << 30) - 1;
        let params = Http3Parameters::default()
            .max_table_size_encoder(limit)
            .max_table_size_decoder(limit);
        assert_eq!(params.get_qpack_settings().max_table_size_encoder, limit);
        assert_eq!(params.get_qpack_settings().max_table_size_decoder, limit);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn max_table_size_encoder_rejects_above_limit() {
        _ = Http3Parameters::default().max_table_size_encoder(1 << 30);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn max_table_size_decoder_rejects_above_limit() {
        _ = Http3Parameters::default().max_table_size_decoder(1 << 30);
    }

    #[test]
    fn http3_datagram_setting() {
        let params = Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(1200))
            .http3_datagram(true);
        assert!(params.get_http3_datagram());
    }
}
