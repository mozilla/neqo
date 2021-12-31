// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, MessageType, Res};
use enumset::{enum_set, EnumSet, EnumSetType};
use neqo_common::Header;

#[derive(EnumSetType, Debug)]
enum PseudoHeaderState {
    Status,
    Method,
    Scheme,
    Authority,
    Path,
    Protocol,
    None,
}

/// Check whether the response is informational(1xx).
/// # Errors
/// Returns an error if response headers do not contain
/// a status header or if the value of the header cannot be parsed.
pub fn is_interim(headers: &[Header]) -> Res<bool> {
    let status = headers.iter().take(1).find(|h| h.name() == ":status");
    if let Some(h) = status {
        #[allow(clippy::map_err_ignore)]
        let status_code = h.value().parse::<i32>().map_err(|_| Error::InvalidHeader)?;
        Ok((100..200).contains(&status_code))
    } else {
        Err(Error::InvalidHeader)
    }
}

fn track_pseudo(
    name: &str,
    state: &mut EnumSet<PseudoHeaderState>,
    message_type: MessageType,
) -> Res<bool> {
    let (pseudo, bit) = if name.starts_with(':') {
        if state.contains(PseudoHeaderState::None) {
            return Err(Error::InvalidHeader);
        }
        let bit = match (message_type, name) {
            (MessageType::Response, ":status") => PseudoHeaderState::Status,
            (MessageType::Request, ":method") => PseudoHeaderState::Method,
            (MessageType::Request, ":scheme") => PseudoHeaderState::Scheme,
            (MessageType::Request, ":authority") => PseudoHeaderState::Authority,
            (MessageType::Request, ":path") => PseudoHeaderState::Path,
            (MessageType::Request, ":protocol") => PseudoHeaderState::Protocol,
            (_, _) => return Err(Error::InvalidHeader),
        };
        (true, bit)
    } else {
        (false, PseudoHeaderState::None)
    };

    if !state.contains(bit) || !pseudo {
        state.insert(bit);
        Ok(pseudo)
    } else {
        Err(Error::InvalidHeader)
    }
}

/// Checks if request/response headers are well formed, i.e. contain
/// allowed pseudo headers and in a right order, etc.
/// # Errors
/// Returns an error if headers are not well formed.
pub fn headers_valid(headers: &[Header], message_type: MessageType) -> Res<()> {
    let mut method_value: Option<&str> = None;
    let mut pseudo_state = EnumSet::new();
    for header in headers {
        let is_pseudo = track_pseudo(header.name(), &mut pseudo_state, message_type)?;

        let mut bytes = header.name().bytes();
        if is_pseudo {
            if header.name() == ":method" {
                method_value = Some(header.value());
            }
            let _ = bytes.next();
        }

        if bytes.any(|b| matches!(b, 0 | 0x10 | 0x13 | 0x3a | 0x41..=0x5a)) {
            return Err(Error::InvalidHeader); // illegal characters.
        }
    }
    // Clear the regular header bit, since we only check pseudo headers below.
    pseudo_state.remove(PseudoHeaderState::None);
    let pseudo_header_mask = match message_type {
        MessageType::Response => enum_set!(PseudoHeaderState::Status),
        MessageType::Request => {
            if method_value == Some(&"CONNECT".to_string()) {
                PseudoHeaderState::Method | PseudoHeaderState::Authority
            } else {
                PseudoHeaderState::Method | PseudoHeaderState::Scheme | PseudoHeaderState::Path
            }
        }
    };

    if (MessageType::Request == message_type)
        && pseudo_state.contains(PseudoHeaderState::Protocol)
        && method_value != Some(&"CONNECT".to_string())
    {
        return Err(Error::InvalidHeader);
    }

    if pseudo_state & pseudo_header_mask != pseudo_header_mask {
        return Err(Error::InvalidHeader);
    }

    Ok(())
}

/// Checks if trailers are well formed, i.e. pseudo headers are not
/// allowed in trailers.
/// # Errors
/// Returns an error if trailers are not well formed.
pub fn trailers_valid(headers: &[Header]) -> Res<()> {
    for header in headers {
        if header.name().starts_with(':') {
            return Err(Error::InvalidHeader);
        }
    }
    Ok(())
}
