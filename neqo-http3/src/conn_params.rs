// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use neqo_common::qdebug;
use neqo_qpack as qpack;
use neqo_transport::ConnectionParameters;

const WEBTRANSPORT_DEFAULT: bool = false;
/// Do not support HTTP Extended CONNECT by default.
const CONNECT_DEFAULT: bool = false;
const HTTP3_DATAGRAM_DEFAULT: bool = true;
/// Default per-session WebTransport flow control limits advertised in SETTINGS.
/// `None` means "do not advertise this setting" (treat as unlimited by peer).
const WT_INITIAL_MAX_DATA_DEFAULT: Option<u64> = None;
const WT_INITIAL_MAX_STREAMS_UNI_DEFAULT: Option<u64> = None;
const WT_INITIAL_MAX_STREAMS_BIDI_DEFAULT: Option<u64> = None;
const WEBTRANSPORT_ASSUME_PEER_RELIABLE_RESET_DEFAULT: bool = false;

#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent, unrelated knob; a builder pattern already avoids \
              boolean-argument confusion at call sites"
)]
pub struct Http3Parameters {
    conn_params: ConnectionParameters,
    qpack_settings: qpack::Settings,
    webtransport: bool,
    /// Per-session initial max data advertised to peer (draft-ietf-webtrans-http3-15).
    /// `None` means do not advertise this setting (treat as unlimited by peer);
    /// `Some(0)` explicitly advertises a limit of zero.
    wt_initial_max_data: Option<u64>,
    /// Per-session initial max unidirectional streams advertised to peer.
    /// `None` means "do not advertise this setting" (peer applies the WebTransport spec default,
    /// currently 0).
    wt_initial_max_streams_uni: Option<u64>,
    /// Per-session initial max bidirectional streams advertised to peer.
    /// `None` means do not advertise this setting; `Some(0)` explicitly
    /// advertises a limit of zero.
    wt_initial_max_streams_bidi: Option<u64>,
    /// HTTP Extended CONNECT
    connect: bool,
    http3_datagram: bool,
    /// See [`Self::webtransport_assume_peer_reliable_reset_for_testing`].
    webtransport_assume_peer_reliable_reset: bool,
}

impl Default for Http3Parameters {
    fn default() -> Self {
        Self {
            conn_params: ConnectionParameters::default(),
            qpack_settings: qpack::Settings::default(),
            webtransport: WEBTRANSPORT_DEFAULT,
            wt_initial_max_data: WT_INITIAL_MAX_DATA_DEFAULT,
            wt_initial_max_streams_uni: WT_INITIAL_MAX_STREAMS_UNI_DEFAULT,
            wt_initial_max_streams_bidi: WT_INITIAL_MAX_STREAMS_BIDI_DEFAULT,
            connect: CONNECT_DEFAULT,
            http3_datagram: HTTP3_DATAGRAM_DEFAULT,
            webtransport_assume_peer_reliable_reset:
                WEBTRANSPORT_ASSUME_PEER_RELIABLE_RESET_DEFAULT,
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

    #[must_use]
    pub const fn qpack(mut self, qpack_settings: qpack::Settings) -> Self {
        self.qpack_settings = qpack_settings;
        self
    }

    /// # Panics
    ///
    /// The table size must be smaller than 1 << 30 by the spec.
    #[must_use]
    pub const fn max_table_size_encoder(mut self, max_table: u64) -> Self {
        self.qpack_settings = self.qpack_settings.max_table_size_encoder(max_table);
        self
    }

    /// # Panics
    ///
    /// The table size must be smaller than 1 << 30 by the spec.
    #[must_use]
    pub const fn max_table_size_decoder(mut self, max_table: u64) -> Self {
        self.qpack_settings = self.qpack_settings.max_table_size_decoder(max_table);
        self
    }

    #[must_use]
    pub const fn get_max_table_size_decoder(&self) -> u64 {
        self.qpack_settings.get_max_table_size_decoder()
    }

    #[must_use]
    pub const fn max_blocked_streams(mut self, max_blocked: u16) -> Self {
        self.qpack_settings = self.qpack_settings.max_blocked_streams(max_blocked);
        self
    }

    #[must_use]
    pub const fn get_max_blocked_streams(&self) -> u16 {
        self.qpack_settings.get_max_blocked_streams()
    }

    #[must_use]
    pub const fn get_qpack_settings(&self) -> &qpack::Settings {
        &self.qpack_settings
    }

    /// Configure WebTransport.
    ///
    /// Note that enabling this has no effect unless you also enable datagrams
    /// ([`Self::http3_datagram`]) and enable datagrams and reliable stream reset in the
    /// transport; see [`Self::webtransport_enabled`].
    ///
    /// Side effect: because WebTransport runs over HTTP Extended CONNECT, enabling WebTransport
    /// also enables Extended CONNECT ([`Self::connect`]).
    #[must_use]
    pub const fn webtransport(mut self, webtransport: bool) -> Self {
        self.webtransport = webtransport;
        self.connect |= webtransport;
        self
    }

    /// Whether WebTransport is enabled.
    ///
    /// Warning: enabling WebTransport via [`Self::webtransport`] will not result in this
    /// returning `true` unless you also have enabled datagrams in both HTTP/3
    /// ([`Self::http3_datagram`]) and QUIC ([`ConnectionParameters::datagram_size`])
    /// as well as reliable reset ([`ConnectionParameters::reliable_stream_reset`]).
    /// This function will return `false` if those features are disabled.
    #[must_use]
    pub fn webtransport_enabled(&self) -> bool {
        if !self.webtransport {
            return false;
        }
        // Enabling WebTransport always enables CONNECT.
        debug_assert!(self.connect);
        // WebTransport over HTTP/3 requires HTTP/3 datagrams (carried in QUIC DATAGRAM frames)
        // and reliable stream reset (to deliver each stream's header even if the stream is
        // reset). Only enable it when all of those are configured locally.
        if !self.http3_datagram {
            qdebug!("WebTransport disabled: SETTINGS_H3_DATAGRAM is not enabled");
            return false;
        }
        if self.conn_params.get_datagram_size() == 0 {
            qdebug!("WebTransport disabled: max_datagram_frame_size transport parameter is 0");
            return false;
        }
        if !self.conn_params.reliable_stream_reset_enabled() {
            qdebug!("WebTransport disabled: reset_stream_at transport parameter is disabled");
            return false;
        }
        true
    }

    /// Skip checking whether the peer actually advertised reliable stream
    /// reset support when negotiating WebTransport, treating it as present
    /// regardless.
    ///
    /// This exists *only* for testing against QUIC server implementations
    /// that do not yet implement `reset_stream_at` (e.g. aioquic, as used by
    /// WPT's HTTP/3 test server as of this writing) but are otherwise usable
    /// for exercising WebTransport features - such as datagrams - that do
    /// not themselves depend on reliable stream reset. Do not enable this
    /// against a production peer: WebTransport streams genuinely need
    /// reliable reset to deliver headers after a reset, and a peer that
    /// doesn't support it will behave incorrectly once actually used for
    /// that.
    #[must_use]
    pub const fn webtransport_assume_peer_reliable_reset_for_testing(
        mut self,
        assume: bool,
    ) -> Self {
        self.webtransport_assume_peer_reliable_reset = assume;
        self
    }

    /// See [`Self::webtransport_assume_peer_reliable_reset_for_testing`].
    #[must_use]
    pub const fn webtransport_assumes_peer_reliable_reset(&self) -> bool {
        self.webtransport_assume_peer_reliable_reset
    }

    /// Set the per-session initial max data advertised to the peer. Pass
    /// `None` to not advertise this setting at all (peer treats it as
    /// unlimited), or `Some(0)` to explicitly advertise a limit of zero.
    #[must_use]
    pub const fn wt_initial_max_data(mut self, max_data: Option<u64>) -> Self {
        self.wt_initial_max_data = max_data;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_data(&self) -> Option<u64> {
        self.wt_initial_max_data
    }

    /// Set the per-session initial max unidirectional streams advertised to
    /// the peer. Pass `None` to not advertise this setting at all, or
    /// `Some(0)` to explicitly advertise a limit of zero.
    #[must_use]
    pub const fn wt_initial_max_streams_uni(mut self, max_streams: Option<u64>) -> Self {
        self.wt_initial_max_streams_uni = max_streams;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_streams_uni(&self) -> Option<u64> {
        self.wt_initial_max_streams_uni
    }

    /// Set the per-session initial max bidirectional streams advertised to
    /// the peer. Pass `None` to not advertise this setting at all, or
    /// `Some(0)` to explicitly advertise a limit of zero.
    #[must_use]
    pub const fn wt_initial_max_streams_bidi(mut self, max_streams: Option<u64>) -> Self {
        self.wt_initial_max_streams_bidi = max_streams;
        self
    }

    #[must_use]
    pub const fn get_wt_initial_max_streams_bidi(&self) -> Option<u64> {
        self.wt_initial_max_streams_bidi
    }

    /// Setter for HTTP Extended CONNECT support.
    ///
    /// Side effect: because WebTransport runs over Extended CONNECT, disabling Extended CONNECT
    /// also disables WebTransport ([`Self::webtransport`]).
    #[must_use]
    pub const fn connect(mut self, connect: bool) -> Self {
        self.connect = connect;
        self.webtransport &= connect;
        self
    }

    /// Getter for HTTP Extended CONNECT support.
    #[must_use]
    pub const fn connect_enabled(&self) -> bool {
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
        assert_eq!(
            params.get_qpack_settings().get_max_table_size_encoder(),
            limit
        );
        assert_eq!(
            params.get_qpack_settings().get_max_table_size_decoder(),
            limit
        );
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
    fn webtransport_requires_datagrams_and_reliable_reset() {
        // Enabled with the default transport parameters (datagrams and reliable_stream_reset on).
        assert!(
            Http3Parameters::default()
                .webtransport(true)
                .webtransport_enabled()
        );

        // Disabled when HTTP/3 datagrams are turned off.
        assert!(
            !Http3Parameters::default()
                .webtransport(true)
                .http3_datagram(false)
                .webtransport_enabled()
        );

        // Disabled when the QUIC datagram frame size is 0.
        assert!(
            !Http3Parameters::default()
                .connection_parameters(ConnectionParameters::default().datagram_size(0))
                .webtransport(true)
                .webtransport_enabled()
        );

        // Disabled when reliable_stream_reset is turned off.
        assert!(
            !Http3Parameters::default()
                .connection_parameters(ConnectionParameters::default().reliable_stream_reset(false))
                .webtransport(true)
                .webtransport_enabled()
        );
    }

    #[test]
    fn webtransport_assume_peer_reliable_reset_for_testing() {
        assert!(
            !Http3Parameters::default().webtransport_assumes_peer_reliable_reset(),
            "off by default, so production behavior is unaffected"
        );
        assert!(
            Http3Parameters::default()
                .webtransport_assume_peer_reliable_reset_for_testing(true)
                .webtransport_assumes_peer_reliable_reset()
        );
        // This is purely a peer-side override: it must not affect the local
        // prerequisite check, which is unrelated (see
        // webtransport_requires_datagrams_and_reliable_reset above).
        assert!(
            !Http3Parameters::default()
                .connection_parameters(ConnectionParameters::default().reliable_stream_reset(false))
                .webtransport(true)
                .webtransport_assume_peer_reliable_reset_for_testing(true)
                .webtransport_enabled()
        );
    }

    #[test]
    fn webtransport_and_connect_are_coupled() {
        // Enabling WebTransport enables Extended CONNECT.
        let p = Http3Parameters::default().webtransport(true);
        assert!(p.connect_enabled());
        assert!(p.webtransport_enabled());

        // Disabling Extended CONNECT disables WebTransport.
        let p = Http3Parameters::default().webtransport(true).connect(false);
        assert!(!p.connect_enabled());
        assert!(!p.webtransport_enabled());

        // The coupling is order-sensitive: a later `webtransport(true)` re-enables Extended
        // CONNECT.
        let p = Http3Parameters::default().connect(false).webtransport(true);
        assert!(p.connect_enabled());
        assert!(p.webtransport_enabled());

        // Extended CONNECT can be enabled on its own without enabling WebTransport.
        let p = Http3Parameters::default().connect(true);
        assert!(p.connect_enabled());
        assert!(!p.webtransport_enabled());
    }

    #[test]
    fn http3_datagram_setting() {
        let params = Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(1200))
            .http3_datagram(true);
        assert!(params.get_http3_datagram());
    }
}
