#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use neqo_common::Decoder;
    use neqo_transport::{addr_valid::AddressValidation, server::ValidateAddress};
    use test_fixture::now;

    // Binary format: [1-byte length] [ip octets: 4 or 16 bytes] [port: 2 bytes BE] [token...]
    let mut dec = Decoder::new(data);
    let Some(ip_bytes) = dec.decode_vec(1) else {
        return;
    };
    let ip = match ip_bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip_bytes).unwrap())),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).unwrap())),
        _ => return,
    };
    let Some(port) = dec.decode_uint::<u16>() else {
        return;
    };
    let peer = SocketAddr::new(ip, port);
    let token = dec.decode_remainder();

    let now = now();
    let Ok(av) = AddressValidation::new(now, ValidateAddress::Always) else {
        return;
    };
    _ = av.validate(token, peer, now);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
