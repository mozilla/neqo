use neqo_crypto::init_db;
use neqo_transport::{Connection, Datagram};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-client", about = "A basic QUIC client.")]
struct Args {
    host: String,
    port: u16,
    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    db: PathBuf,

    #[structopt(short = "4", long)]
    ipv4: bool,
    #[structopt(short = "6", long)]
    ipv6: bool,
}

impl Args {
    fn addr(&self) -> SocketAddr {
        self.to_socket_addrs()
            .expect("Remote address error")
            .next()
            .expect("No remote addresses")
    }

    fn bind(&self) -> BindAnyType {
        match (self.ipv4, self.ipv6) {
            (true, false) => BindAnyType::Ipv4,
            (false, true) => BindAnyType::Ipv6,
            _ => BindAnyType::All,
        }
    }
}

impl ToSocketAddrs for Args {
    type Iter = ::std::option::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        (
            IpAddr::from_str(self.host.as_str()).expect("Invalid address"),
            self.port,
        )
            .to_socket_addrs()
    }
}

#[derive(Clone, Copy, Debug)]
enum BindAnyType {
    All,
    Ipv4,
    Ipv6,
    Done,
}

impl ToSocketAddrs for BindAnyType {
    type Iter = BindAny;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        Ok(BindAny(*self))
    }
}

struct BindAny(BindAnyType);

impl Iterator for BindAny {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        let (res, nxt) = match self.0 {
            BindAnyType::All => (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
                BindAnyType::Ipv6,
            ),
            BindAnyType::Ipv4 => (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
                BindAnyType::Done,
            ),
            BindAnyType::Ipv6 => (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
                BindAnyType::Done,
            ),
            _ => return None,
        };
        self.0 = nxt;
        Some(res)
    }
}

fn main() {
    let args = Args::from_args();
    init_db(args.db.clone());

    let socket = UdpSocket::bind(args.bind()).expect("Unable to bind UDP socket");
    socket.connect(&args).expect("Unable to connect UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let remote_addr = args.addr();
    let mut client = Connection::new_client(args.host.as_str(), local_addr, remote_addr);

    let buf = &mut [0u8; 2048];
    let mut in_dgrams = Vec::new();
    loop {
        let out_dgrams = client
            .process(in_dgrams.drain(..))
            .expect("Error processing input");
        in_dgrams.clear();

        for d in out_dgrams {
            let sent = socket.send(&d[..]).expect("Error sending datagram");
            if sent != d.len() {
                eprintln!("Unable to send all {} bytes of datagram", d.len());
            }
        }

        let sz = socket.recv(&mut buf[..]).expect("UDP error");
        if sz == buf.len() {
            eprintln!("Received more than {} bytes", buf.len());
        }
        if sz > 0 {
            in_dgrams.push(Datagram::new(remote_addr, local_addr, &buf[..sz]));
        }
    }
}
