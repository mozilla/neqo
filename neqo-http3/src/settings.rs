// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::Deref;

use neqo_common::{Buffer, Decoder, Encoder, qdebug};
use nss::{ZeroRttCheckResult, ZeroRttChecker};

use crate::{Error, Http3Parameters, Res};

type SettingsType = u64;

/// Increment this version number if a new setting is added and that might
/// cause 0-RTT to be accepted where shouldn't be.
const SETTINGS_ZERO_RTT_VERSION: u64 = 2;

const SETTINGS_MAX_HEADER_LIST_SIZE: SettingsType = 0x6;
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: SettingsType = 0x1;
const SETTINGS_QPACK_BLOCKED_STREAMS: SettingsType = 0x7;
// draft-ietf-webtrans-http3-07#section-8.2
const SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT07: SettingsType = 0xc671_706a;
// draft-ietf-webtrans-http3-15#section-9.2
const SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15: SettingsType = 0x2c7c_f000;
// draft-ietf-masque-h3-datagram-04.
// We also use this old value because the current web-platform test only supports
// this value.
const SETTINGS_H3_DATAGRAM_DRAFT04: SettingsType = 0x00ff_d277;

const SETTINGS_H3_DATAGRAM: SettingsType = 0x33;

/// Advertises support for HTTP Extended CONNECT.
///
/// See <https://www.rfc-editor.org/rfc/rfc9220#section-5>
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: SettingsType = 0x08;

pub const H3_RESERVED_SETTINGS: &[SettingsType] = &[0x2, 0x3, 0x4, 0x5];

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum HSettingType {
    MaxHeaderListSize,
    MaxTableCapacity,
    BlockedStreams,
    EnableWebTransportDraft07,
    EnableWebTransportDraft15,
    EnableH3Datagram,
    EnableConnect,
}

const fn hsetting_default(setting_type: HSettingType) -> u64 {
    match setting_type {
        HSettingType::MaxHeaderListSize => 1 << 62,
        HSettingType::MaxTableCapacity
        | HSettingType::BlockedStreams
        | HSettingType::EnableWebTransportDraft07
        | HSettingType::EnableWebTransportDraft15
        | HSettingType::EnableH3Datagram
        | HSettingType::EnableConnect => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HSetting {
    pub setting_type: HSettingType,
    pub value: u64,
}

impl HSetting {
    #[must_use]
    pub const fn new(setting_type: HSettingType, value: u64) -> Self {
        Self {
            setting_type,
            value,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HSettings {
    settings: Vec<HSetting>,
}

impl HSettings {
    #[must_use]
    pub fn new(settings: &[HSetting]) -> Self {
        Self {
            settings: settings.to_vec(),
        }
    }

    #[must_use]
    pub fn get(&self, setting: HSettingType) -> u64 {
        self.settings
            .iter()
            .find(|s| s.setting_type == setting)
            .map_or_else(|| hsetting_default(setting), |v| v.value)
    }

    pub fn encode_frame_contents<B: Buffer>(&self, enc: &mut Encoder<B>) {
        enc.encode_vvec_with(|enc_inner| {
            #[cfg(feature = "build-fuzzing-corpus")]
            let start = enc_inner.len();

            for iter in &self.settings {
                match iter.setting_type {
                    HSettingType::MaxHeaderListSize => {
                        enc_inner.encode_varint(SETTINGS_MAX_HEADER_LIST_SIZE);
                        enc_inner.encode_varint(iter.value);
                    }
                    HSettingType::MaxTableCapacity => {
                        enc_inner.encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
                        enc_inner.encode_varint(iter.value);
                    }
                    HSettingType::BlockedStreams => {
                        enc_inner.encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS);
                        enc_inner.encode_varint(iter.value);
                    }
                    HSettingType::EnableWebTransportDraft15 => {
                        enc_inner.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15);
                        enc_inner.encode_varint(iter.value);
                    }
                    HSettingType::EnableWebTransportDraft07 => {
                        // We never encode draft-07 ourselves; only decode it for compat.
                    }
                    HSettingType::EnableH3Datagram => {
                        if iter.value == 1 {
                            enc_inner.encode_varint(SETTINGS_H3_DATAGRAM_DRAFT04);
                            enc_inner.encode_varint(iter.value);
                            enc_inner.encode_varint(SETTINGS_H3_DATAGRAM);
                            enc_inner.encode_varint(iter.value);
                        }
                    }
                    HSettingType::EnableConnect => {
                        if iter.value == 1 {
                            enc_inner.encode_varint(SETTINGS_ENABLE_CONNECT_PROTOCOL);
                            enc_inner.encode_varint(iter.value);
                        }
                    }
                }
            }

            #[cfg(feature = "build-fuzzing-corpus")]
            neqo_common::write_item_to_fuzzing_corpus("hsettings", &enc_inner.as_ref()[start..]);
        });
    }

    /// # Errors
    ///
    /// Returns an error if settings types are reserved of settings value are not permitted.
    pub fn decode_frame_contents(&mut self, dec: &mut Decoder) -> Res<()> {
        #[cfg(feature = "build-fuzzing-corpus")]
        neqo_common::write_item_to_fuzzing_corpus("hsettings", dec.as_ref());

        while dec.remaining() > 0 {
            let t = dec.decode_varint();
            let v = dec.decode_varint();

            if let Some(settings_type) = t
                && H3_RESERVED_SETTINGS.contains(&settings_type)
            {
                return Err(Error::HttpSettings);
            }
            match (t, v) {
                (Some(SETTINGS_MAX_HEADER_LIST_SIZE), Some(value)) => self
                    .settings
                    .push(HSetting::new(HSettingType::MaxHeaderListSize, value)),
                (Some(SETTINGS_QPACK_MAX_TABLE_CAPACITY), Some(value)) => self
                    .settings
                    .push(HSetting::new(HSettingType::MaxTableCapacity, value)),
                (Some(SETTINGS_QPACK_BLOCKED_STREAMS), Some(value)) => self
                    .settings
                    .push(HSetting::new(HSettingType::BlockedStreams, value)),
                (Some(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15), Some(value)) => {
                    if value > 1 {
                        return Err(Error::HttpSettings);
                    }
                    self.settings.push(HSetting::new(
                        HSettingType::EnableWebTransportDraft15,
                        value,
                    ));
                }
                (Some(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT07), Some(value)) => {
                    // draft-ietf-webtrans-http3-07's SETTINGS_WEBTRANSPORT_MAX_SESSIONS
                    // is an integer (max concurrent sessions the peer will accept), not
                    // a boolean: 0 means unsupported, any value > 0 signals support.
                    self.settings.push(HSetting::new(
                        HSettingType::EnableWebTransportDraft07,
                        value,
                    ));
                }
                (Some(SETTINGS_H3_DATAGRAM_DRAFT04), Some(value)) => {
                    if value > 1 {
                        return Err(Error::HttpSettings);
                    }
                    if !self
                        .settings
                        .iter()
                        .any(|s| s.setting_type == HSettingType::EnableH3Datagram)
                    {
                        self.settings
                            .push(HSetting::new(HSettingType::EnableH3Datagram, value));
                    }
                }
                (Some(SETTINGS_H3_DATAGRAM), Some(value)) => {
                    if value > 1 {
                        return Err(Error::HttpSettings);
                    }
                    if !self
                        .settings
                        .iter()
                        .any(|s| s.setting_type == HSettingType::EnableH3Datagram)
                    {
                        self.settings
                            .push(HSetting::new(HSettingType::EnableH3Datagram, value));
                    }
                }
                (Some(SETTINGS_ENABLE_CONNECT_PROTOCOL), Some(value)) => {
                    if value > 1 {
                        return Err(Error::HttpSettings);
                    }
                    self.settings
                        .push(HSetting::new(HSettingType::EnableConnect, value));
                }
                (Some(t), Some(v)) => {
                    qdebug!("Ignoring unknown setting type {t} with value {v}");
                }
                _ => return Err(Error::NotEnoughData),
            }
        }
        Ok(())
    }
}

impl Deref for HSettings {
    type Target = [HSetting];
    fn deref(&self) -> &Self::Target {
        &self.settings
    }
}

impl From<&Http3Parameters> for HSettings {
    fn from(conn_param: &Http3Parameters) -> Self {
        Self {
            settings: vec![
                HSetting {
                    setting_type: HSettingType::MaxTableCapacity,
                    value: conn_param.get_max_table_size_decoder(),
                },
                HSetting {
                    setting_type: HSettingType::BlockedStreams,
                    value: u64::from(conn_param.get_max_blocked_streams()),
                },
                // We only ever advertise draft-15 support to peers; draft-07 is
                // decode-only compatibility for peers that advertise it to us
                // (see `ExtendedConnectFeature::handle_settings`). A peer that
                // understands draft-07 only, and not draft-15's setting
                // identifier, will not see us as WebTransport-capable.
                HSetting {
                    setting_type: HSettingType::EnableWebTransportDraft15,
                    value: u64::from(conn_param.get_webtransport()),
                },
                HSetting {
                    setting_type: HSettingType::EnableH3Datagram,
                    value: u64::from(conn_param.get_http3_datagram()),
                },
                HSetting {
                    setting_type: HSettingType::EnableConnect,
                    value: u64::from(conn_param.get_connect()),
                },
            ],
        }
    }
}

#[derive(Debug)]
pub struct HttpZeroRttChecker {
    settings: Http3Parameters,
}

impl HttpZeroRttChecker {
    /// Right now we only have QPACK settings, so that is all this takes.
    #[must_use]
    pub const fn new(settings: Http3Parameters) -> Self {
        Self { settings }
    }

    /// Save the settings that matter for 0-RTT.
    #[must_use]
    pub fn save(settings: &Http3Parameters) -> Vec<u8> {
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ZERO_RTT_VERSION)
            .encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY)
            .encode_varint(settings.get_max_table_size_decoder())
            .encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS)
            .encode_varint(settings.get_max_blocked_streams());
        if settings.get_webtransport() {
            enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15)
                .encode_varint(true);
        }
        if settings.get_http3_datagram() {
            enc.encode_varint(SETTINGS_H3_DATAGRAM).encode_varint(true);
        }
        enc.into()
    }
}

impl ZeroRttChecker for HttpZeroRttChecker {
    fn check(&self, token: &[u8]) -> ZeroRttCheckResult {
        let mut dec = Decoder::from(token);

        // Read and check the version.
        if let Some(version) = dec.decode_varint() {
            if version != SETTINGS_ZERO_RTT_VERSION {
                return ZeroRttCheckResult::Reject;
            }
        } else {
            return ZeroRttCheckResult::Fail;
        }

        // Now treat the rest as a settings frame.
        let mut settings = HSettings::new(&[]);
        if settings.decode_frame_contents(&mut dec).is_err() {
            return ZeroRttCheckResult::Fail;
        }
        if settings.iter().all(|setting| match setting.setting_type {
            HSettingType::BlockedStreams => {
                u64::from(self.settings.get_max_blocked_streams()) >= setting.value
            }
            HSettingType::MaxTableCapacity => {
                self.settings.get_max_table_size_decoder() >= setting.value
            }
            HSettingType::EnableWebTransportDraft15 => {
                if setting.value > 1 {
                    return false;
                }
                let value = setting.value == 1;
                self.settings.get_webtransport() || !value
            }
            // Draft-07 in a 0-RTT token: always accept, we handle both versions.
            HSettingType::EnableWebTransportDraft07 | HSettingType::MaxHeaderListSize => true,
            HSettingType::EnableH3Datagram => {
                if setting.value > 1 {
                    return false;
                }
                let value = setting.value == 1;
                self.settings.get_http3_datagram() || !value
            }
            HSettingType::EnableConnect => {
                if setting.value > 1 {
                    return false;
                }
                let value = setting.value == 1;
                self.settings.get_connect() || !value
            }
        }) {
            ZeroRttCheckResult::Accept
        } else {
            ZeroRttCheckResult::Reject
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn unknown_setting_type_ignored() {
        let mut enc = Encoder::default();

        // Add a known setting.
        enc.encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        enc.encode_varint(1024u64);

        // Add an unknown setting type.
        let unknown_setting_type = u64::from(u32::MAX);
        enc.encode_varint(unknown_setting_type);
        enc.encode_varint(42u64);

        // Add another known setting.
        enc.encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS);
        enc.encode_varint(100u64);

        let mut dec = enc.as_decoder();

        let mut settings = HSettings::new(&[]);
        settings
            .decode_frame_contents(&mut dec)
            .expect("succeeds despite unknown setting");

        // Should only contain the known settings.
        assert_eq!(settings.len(), 2);
        assert_eq!(settings.get(HSettingType::MaxTableCapacity), 1024);
        assert_eq!(settings.get(HSettingType::BlockedStreams), 100);
    }

    #[test]
    fn not_enough_data_error() {
        let mut enc = Encoder::default();

        // Add a complete setting.
        enc.encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        enc.encode_varint(1024u64);

        // Add an incomplete setting.
        enc.encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS);

        let mut dec = enc.as_decoder();

        let mut settings = HSettings::new(&[]);
        assert_eq!(
            settings.decode_frame_contents(&mut dec),
            Err(Error::NotEnoughData)
        );
    }

    #[test]
    fn datagram_settings() {
        for setting in [SETTINGS_H3_DATAGRAM, SETTINGS_H3_DATAGRAM_DRAFT04] {
            // Valid value accepted.
            let mut enc = Encoder::default();
            enc.encode_varint(setting).encode_varint(1u64);
            let mut s = HSettings::new(&[]);
            s.decode_frame_contents(&mut enc.as_decoder()).unwrap();
            assert_eq!(s.get(HSettingType::EnableH3Datagram), 1);

            // Invalid value rejected.
            enc = Encoder::default();
            enc.encode_varint(setting).encode_varint(2u64);
            let mut s = HSettings::new(&[]);
            assert_eq!(
                s.decode_frame_contents(&mut enc.as_decoder()),
                Err(Error::HttpSettings)
            );
        }

        // Duplicate: first wins.
        for (first, second, expected) in [
            (SETTINGS_H3_DATAGRAM, SETTINGS_H3_DATAGRAM_DRAFT04, 1),
            (SETTINGS_H3_DATAGRAM_DRAFT04, SETTINGS_H3_DATAGRAM, 0),
        ] {
            let mut enc = Encoder::default();
            enc.encode_varint(first).encode_varint(expected);
            enc.encode_varint(second).encode_varint(1 - expected);
            let mut s = HSettings::new(&[]);
            s.decode_frame_contents(&mut enc.as_decoder()).unwrap();
            assert_eq!(s.get(HSettingType::EnableH3Datagram), expected);
        }
    }

    #[test]
    fn webtransport_draft15_setting() {
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15)
            .encode_varint(1u64);
        let mut s = HSettings::new(&[]);
        s.decode_frame_contents(&mut enc.as_decoder()).unwrap();
        assert_eq!(s.get(HSettingType::EnableWebTransportDraft15), 1);

        // Invalid value rejected.
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15)
            .encode_varint(2u64);
        let mut s = HSettings::new(&[]);
        assert_eq!(
            s.decode_frame_contents(&mut enc.as_decoder()),
            Err(Error::HttpSettings)
        );
    }

    /// draft-02's `SETTINGS_ENABLE_WEBTRANSPORT` is what neqo advertised before
    /// draft-15 support landed. Dropping it is deliberate: we now speak draft-15
    /// and accept draft-07, so a peer that only sends the draft-02 identifier does
    /// not negotiate WebTransport with us.
    #[test]
    fn legacy_draft02_webtransport_setting_is_not_recognised() {
        const SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT02: SettingsType = 0x2b60_3742;

        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT02)
            .encode_varint(1u64);
        let mut s = HSettings::new(&[]);
        s.decode_frame_contents(&mut enc.as_decoder()).unwrap();

        assert_eq!(s.get(HSettingType::EnableWebTransportDraft15), 0);
        assert_eq!(s.get(HSettingType::EnableWebTransportDraft07), 0);
    }

    #[test]
    fn webtransport_draft07_setting() {
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT07)
            .encode_varint(1u64);
        let mut s = HSettings::new(&[]);
        s.decode_frame_contents(&mut enc.as_decoder()).unwrap();
        assert_eq!(s.get(HSettingType::EnableWebTransportDraft07), 1);
        // Draft-15 not affected.
        assert_eq!(s.get(HSettingType::EnableWebTransportDraft15), 0);
    }

    #[test]
    fn webtransport_draft07_setting_is_a_count_not_a_bool() {
        // SETTINGS_WEBTRANSPORT_MAX_SESSIONS (draft-ietf-webtrans-http3-07) is a
        // count of concurrent sessions the peer will accept, not a boolean; a
        // legitimate peer may advertise any value > 1, and that must not be
        // rejected as an invalid HTTP/3 setting.
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT07)
            .encode_varint(5u64);
        let mut s = HSettings::new(&[]);
        s.decode_frame_contents(&mut enc.as_decoder()).unwrap();
        assert_eq!(s.get(HSettingType::EnableWebTransportDraft07), 5);
    }

    fn make_0rtt_token(settings: &[(u64, u64)]) -> Vec<u8> {
        let mut enc = Encoder::default();
        enc.encode_varint(SETTINGS_ZERO_RTT_VERSION);
        for (k, v) in settings {
            enc.encode_varint(*k).encode_varint(*v);
        }
        enc.into()
    }

    #[test]
    fn zero_rtt_checker() {
        use neqo_transport::ConnectionParameters;
        use nss::{ZeroRttCheckResult, ZeroRttChecker as _};

        use crate::Http3Parameters;

        // Server with datagram enabled, connect disabled.
        let params = Http3Parameters::default()
            .connection_parameters(ConnectionParameters::default().datagram_size(1200));
        let checker = HttpZeroRttChecker::new(params);

        // Token requests datagram=1: accepted (server has it).
        let token = make_0rtt_token(&[(SETTINGS_H3_DATAGRAM, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);

        // Token requests datagram=0: accepted (not requesting feature).
        let token = make_0rtt_token(&[(SETTINGS_H3_DATAGRAM, 0)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);

        // Token with invalid datagram value (>1): fails decode.
        let token = make_0rtt_token(&[(SETTINGS_H3_DATAGRAM, 2)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Fail);

        // Token requests connect=1 but server doesn't have it: rejected.
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Reject);

        // Server with connect enabled.
        let params = Http3Parameters::default().connect(true);
        let checker = HttpZeroRttChecker::new(params);
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);

        // Invalid token (truncated): rejected (remaining bytes interpreted as wrong version).
        assert_eq!(checker.check(&token[1..]), ZeroRttCheckResult::Reject);

        // Empty token: fails.
        assert_eq!(checker.check(&[]), ZeroRttCheckResult::Fail);
    }

    #[test]
    fn zero_rtt_checker_webtransport() {
        use nss::{ZeroRttCheckResult, ZeroRttChecker as _};

        use crate::Http3Parameters;

        // Server with WebTransport enabled.
        let checker = HttpZeroRttChecker::new(Http3Parameters::default().webtransport(true));

        // draft-15 requested and supported: accepted.
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);

        // draft-07 token is always accepted (both versions are handled).
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT07, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);

        // Server without WebTransport: a token requesting draft-15=1 is rejected.
        let checker = HttpZeroRttChecker::new(Http3Parameters::default());
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15, 1)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Reject);

        // ...but draft-15=0 (not requesting the feature) is accepted.
        let token = make_0rtt_token(&[(SETTINGS_ENABLE_WEB_TRANSPORT_DRAFT15, 0)]);
        assert_eq!(checker.check(&token), ZeroRttCheckResult::Accept);
    }
}
