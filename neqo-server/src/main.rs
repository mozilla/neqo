use neqo_crypto::init_db;
use neqo_transport::{Connection, Datagram};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "neqo-client", about = "A basic QUIC client.")]
struct Args {
    #[structopt(short = "h", long)]
    /// Optional local address to bind to, defaults to the unspecified address.
    host: Option<String>,
    /// Port number.
    port: u16,

    #[structopt(short = "d", long, default_value = "./db", parse(from_os_str))]
    /// NSS database directory.
    db: PathBuf,
    #[structopt(short = "k", long)]
    /// Name of keys from NSS database.
    key: Vec<String>,

    #[structopt(short = "4", long)]
    /// Restrict to IPv4.
    ipv4: bool,
    #[structopt(short = "6", long)]
    /// Restrict to IPv6.
    ipv6: bool,
}

impl Args {
    fn bind(&self) -> SocketAddr {
        match (&self.host, self.ipv4, self.ipv6) {
            (Some(..), ..) => self.to_socket_addrs()
                .expect("Remote address error")
                .next()
                .expect("No remote addresses"),
            (_, false, true)  => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), self.port),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), self.port),
        }
    }
}

impl ToSocketAddrs for Args {
    type Iter = ::std::option::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> ::std::io::Result<Self::Iter> {
        (
            IpAddr::from_str(self.host.as_ref().unwrap().as_str()).expect("Invalid address"),
            self.port,
        )
            .to_socket_addrs()
    }
}

// TODO(mt): implement a server that can handle multiple connections.
fn main() {
    let args = Args::from_args();
    init_db(args.db.clone());

    // TODO(mt): listen on both v4 and v6.
    let socket = UdpSocket::bind(args.bind()).expect("Unable to bind UDP socket");

    let local_addr = socket.local_addr().expect("Socket local address not bound");
    let mut server = Connection::new_server(args.key);

    let buf = &mut [0u8; 2048];
    let mut in_dgrams = Vec::new();
    loop {
        let (sz, remote_addr) = socket.recv_from(&mut buf[..]).expect("UDP error");
        if sz == buf.len() {
            eprintln!("Might have received more than {} bytes", buf.len());
            continue;
        }
        if sz > 0 {
            in_dgrams.push(Datagram::new(remote_addr, local_addr, &buf[..sz]));
        }

        let out_dgrams = server
            .process(in_dgrams.drain(..))
            .expect("Error processing input");

        for d in out_dgrams {
            let sent = socket.send(&d[..]).expect("Error sending datagram");
            if sent != d.len() {
                eprintln!("Unable to send all {} bytes of datagram", d.len());
            }
        }
    }
}
