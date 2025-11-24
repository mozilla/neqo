#![cfg_attr(all(fuzzing, not(windows)), no_main)]

#[cfg(all(fuzzing, not(windows)))]
use libfuzzer_sys::fuzz_target;

#[cfg(all(fuzzing, not(windows)))]
fuzz_target!(|data: &[u8]| {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use neqo_transport::{addr_valid::AddressValidation, server::ValidateAddress};
    use test_fixture::now;

    // Binary format: [4 or 6] [ip octets: 4 or 16 bytes] [port: 2 bytes BE] [token...]
    let (peer, token) = match data.first() {
        Some(4) if data.len() >= 7 => {
            let ip = Ipv4Addr::from([data[1], data[2], data[3], data[4]]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            (SocketAddr::new(IpAddr::V4(ip), port), &data[7..])
        }
        Some(6) if data.len() >= 19 => {
            let octets: [u8; 16] = data[1..17].try_into().expect("length checked");
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            (SocketAddr::new(IpAddr::V6(ip), port), &data[19..])
        }
        _ => return,
    };

    let now = now();
    let Ok(av) = AddressValidation::new(now, ValidateAddress::Always) else {
        return;
    };
    _ = av.validate(token, peer, now);
});

#[cfg(any(not(fuzzing), windows))]
fn main() {}
