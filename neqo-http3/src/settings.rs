// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::Deref;

use neqo_common::{qdebug, Buffer, Decoder, Encoder};
use neqo_crypto::{ZeroRttCheckResult, ZeroRttChecker};

use crate::{Error, Http3Parameters, Res};

type SettingsType = u64;

/// Increment this version number if a new setting is added and that might
/// cause 0-RTT to be accepted where shouldn't be.
const SETTINGS_ZERO_RTT_VERSION: u64 = 1;

const SETTINGS_MAX_HEADER_LIST_SIZE: SettingsType = 0x6;
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: SettingsType = 0x1;
const SETTINGS_QPACK_BLOCKED_STREAMS: SettingsType = 0x7;
const SETTINGS_ENABLE_WEB_TRANSPORT: SettingsType = 0x2b60_3742;
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
    EnableWebTransport,
    EnableH3Datagram,
    EnableConnect,
}

const fn hsetting_default(setting_type: HSettingType) -> u64 {
    match setting_type {
        HSettingType::MaxHeaderListSize => 1 << 62,
        HSettingType::MaxTableCapacity
        | HSettingType::BlockedStreams
        | HSettingType::EnableWebTransport
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
                    HSettingType::EnableWebTransport => {
                        enc_inner.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT);
                        enc_inner.encode_varint(iter.value);
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
        });
    }

    /// # Errors
    ///
    /// Returns an error if settings types are reserved of settings value are not permitted.
    pub fn decode_frame_contents(&mut self, dec: &mut Decoder) -> Res<()> {
        while dec.remaining() > 0 {
            let t = dec.decode_varint();
            let v = dec.decode_varint();

            if let Some(settings_type) = t {
                if H3_RESERVED_SETTINGS.contains(&settings_type) {
                    return Err(Error::HttpSettings);
                }
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
                (Some(SETTINGS_ENABLE_WEB_TRANSPORT), Some(value)) => {
                    if value > 1 {
                        return Err(Error::HttpSettings);
                    }
                    self.settings
                        .push(HSetting::new(HSettingType::EnableWebTransport, value));
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
                HSetting {
                    setting_type: HSettingType::EnableWebTransport,
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
        let mut enc = Encoder::new();
        enc.encode_varint(SETTINGS_ZERO_RTT_VERSION)
            .encode_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY)
            .encode_varint(settings.get_max_table_size_decoder())
            .encode_varint(SETTINGS_QPACK_BLOCKED_STREAMS)
            .encode_varint(settings.get_max_blocked_streams());
        if settings.get_webtransport() {
            enc.encode_varint(SETTINGS_ENABLE_WEB_TRANSPORT)
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
            HSettingType::EnableWebTransport => {
                if setting.value > 1 {
                    return false;
                }
                let value = setting.value == 1;
                self.settings.get_webtransport() || !value
            }
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
            HSettingType::MaxHeaderListSize => true,
        }) {
            ZeroRttCheckResult::Accept
        } else {
            ZeroRttCheckResult::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use neqo_common::Encoder;

    use super::*;

    #[test]
    fn unknown_setting_type_ignored() {
        let mut enc = Encoder::new();

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
        let mut enc = Encoder::new();

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
}
