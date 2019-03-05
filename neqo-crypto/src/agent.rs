use crate::agentio::{emit_record, ingest_record, AgentIo, METHODS};
pub use crate::agentio::{Record, RecordList};
use crate::constants::*;
use crate::err::{Error, Res};
use crate::initialized;
use crate::p11;
use crate::prio;
use crate::result;
use crate::secrets::Secrets;
use crate::ssl;

use std::ffi::CString;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_uint, c_void};
use std::ptr::{null, null_mut, NonNull};

#[derive(Clone, Debug, PartialEq)]
pub enum HandshakeState {
    New,
    InProgress,
    AuthenticationPending,
    Authenticated,
    Complete,
    Failed(Error),
}

pub struct SecretAgentPreInfo {
    info: ssl::SSLPreliminaryChannelInfo,
}

macro_rules! preinfo_arg {
    ($v:ident, $m:ident, $f:ident: $t:ident) => {
        pub fn $v(&self) -> Option<$t> {
            match self.info.valuesSet & ssl::$m {
                0 => None,
                _ => Some(self.info.$f as $t)
            }
        }
    };
    ($v:ident, $m:ident, $f:ident: $t:ident,) => {
        preinfo_arg!($v, $m, $f: $t);
    }
}

impl SecretAgentPreInfo {
    fn new(fd: *mut ssl::PRFileDesc) -> Res<SecretAgentPreInfo> {
        let mut info: ssl::SSLPreliminaryChannelInfo = unsafe { mem::uninitialized() };
        let rv = unsafe {
            ssl::SSL_GetPreliminaryChannelInfo(
                fd,
                &mut info,
                mem::size_of::<ssl::SSLPreliminaryChannelInfo>() as ssl::PRUint32,
            )
        };
        result::result(rv)?;
        Ok(SecretAgentPreInfo { info })
    }

    preinfo_arg!(version, ssl_preinfo_version, protocolVersion: Version);
    preinfo_arg!(cipher_suite, ssl_preinfo_cipher_suite, cipherSuite: Cipher);

    pub fn early_data(&self) -> bool {
        self.info.canSendEarlyData != 0
    }

    pub fn max_early_data(&self) -> usize {
        self.info.maxEarlyDataSize as usize
    }

    preinfo_arg!(
        early_data_cipher,
        ssl_preinfo_0rtt_cipher_suite,
        zeroRttCipherSuite: Cipher,
    );
}

#[derive(Debug, Default)]
pub struct SecretAgentInfo {
    ver: Version,
    cipher: Cipher,
    group: Group,
    early_data: bool,
    alpn: Option<String>,
}

impl SecretAgentInfo {
    fn new(fd: *mut ssl::PRFileDesc) -> Res<SecretAgentInfo> {
        let mut alpn_state = ssl::SSLNextProtoState::SSL_NEXT_PROTO_NO_SUPPORT;
        let mut chosen = vec![0u8; 255];
        let mut chosen_len: c_uint = 0;
        let rv = unsafe {
            ssl::SSL_GetNextProto(
                fd,
                &mut alpn_state,
                chosen.as_mut_ptr(),
                &mut chosen_len,
                chosen.len() as c_uint,
            )
        };
        result::result(rv)?;
        let alpn = match alpn_state {
            ssl::SSLNextProtoState::SSL_NEXT_PROTO_NEGOTIATED
            | ssl::SSLNextProtoState::SSL_NEXT_PROTO_SELECTED => {
                chosen.truncate(chosen_len as usize);
                Some(match String::from_utf8(chosen) {
                    Ok(a) => a,
                    _ => return Err(Error::InternalError),
                })
            }
            _ => None,
        };

        let mut info: ssl::SSLChannelInfo = unsafe { mem::uninitialized() };
        let rv = unsafe {
            ssl::SSL_GetChannelInfo(
                fd,
                &mut info,
                mem::size_of::<ssl::SSLChannelInfo>() as ssl::PRUint32,
            )
        };
        result::result(rv)?;
        Ok(SecretAgentInfo {
            ver: info.protocolVersion as Version,
            cipher: info.cipherSuite as Cipher,
            group: info.keaGroup as Group,
            early_data: info.earlyDataAccepted != 0,
            alpn,
        })
    }

    pub fn version(&self) -> Version {
        self.ver
    }
    pub fn cipher_suite(&self) -> Cipher {
        self.cipher
    }
    pub fn key_exchange(&self) -> Group {
        self.group
    }
    pub fn early_data_accepted(&self) -> bool {
        self.early_data
    }
    pub fn alpn(&self) -> Option<&String> {
        self.alpn.as_ref()
    }
}

// SecretAgent holds the common parts of client and server.
#[derive(Debug)]
pub struct SecretAgent {
    fd: *mut ssl::PRFileDesc,
    secrets: Secrets,
    raw: Option<bool>,
    io: Box<AgentIo>,
    st: HandshakeState,
    auth_required: Box<bool>,

    inf: Option<SecretAgentInfo>,
}

impl SecretAgent {
    fn new() -> Res<SecretAgent> {
        let mut agent = SecretAgent {
            fd: null_mut(),
            secrets: Default::default(),
            raw: None,
            io: Box::new(AgentIo::new()),
            st: HandshakeState::New,
            auth_required: Box::new(false),

            inf: Default::default(),
        };
        agent.create_fd()?;
        Ok(agent)
    }

    // Create a new SSL file descriptor.
    //
    // Note that we create separate bindings for PRFileDesc as both
    // ssl::PRFileDesc and prio::PRFileDesc.  This keeps the bindings
    // minimal, but it means that the two forms need casts to translate
    // between them.  ssl::PRFileDesc is left as an opaque type, as the
    // ssl::SSL_* APIs only need an opaque type.
    fn create_fd(&mut self) -> Res<()> {
        assert!(initialized());

        let label = CString::new("sslwrapper").expect("cstring failed");
        let id = unsafe { prio::PR_GetUniqueIdentity(label.as_ptr()) };

        let base_fd = unsafe { prio::PR_CreateIOLayerStub(id, METHODS) };
        if base_fd.is_null() {
            return Err(Error::CreateSslSocket);
        }
        let fd = unsafe {
            (*base_fd).secret = &mut *self.io as *mut AgentIo as *mut _;
            ssl::SSL_ImportFD(null_mut(), base_fd as *mut ssl::PRFileDesc)
        };
        if fd.is_null() {
            return Err(Error::CreateSslSocket);
        }
        mem::forget(base_fd); // Free the base.
        self.fd = fd;
        Ok(())
    }

    unsafe extern "C" fn auth_complete_hook(
        arg: *mut c_void,
        _fd: *mut ssl::PRFileDesc,
        _check_sig: ssl::PRBool,
        _is_server: ssl::PRBool,
    ) -> ssl::SECStatus {
        let auth_required_ptr = arg as *mut bool;
        *auth_required_ptr = true;
        // NSS insists on getting SECWouldBlock here rather than accepting
        // the usual combination of PR_WOULD_BLOCK_ERROR and SECFailure.
        // This will change when Bug 1471126 lands.
        ssl::_SECStatus_SECWouldBlock
    }

    // Ready this for connecting.
    fn ready(&mut self, is_server: bool) -> Res<()> {
        result::result(unsafe {
            ssl::SSL_AuthCertificateHook(
                self.fd,
                Some(SecretAgent::auth_complete_hook),
                &mut *self.auth_required as *mut bool as *mut c_void,
            )
        })?;
        self.configure()?;
        result::result(unsafe { ssl::SSL_ResetHandshake(self.fd, is_server as ssl::PRBool) })
    }

    pub fn set_version_range(&mut self, min: Version, max: Version) -> Res<()> {
        let range = ssl::SSLVersionRange {
            min: min as ssl::PRUint16,
            max: max as ssl::PRUint16,
        };
        result::result(unsafe { ssl::SSL_VersionRangeSet(self.fd, &range) })
    }

    pub fn enable_ciphers(&mut self, ciphers: &[Cipher]) -> Res<()> {
        let all_ciphers = unsafe { ssl::SSL_GetImplementedCiphers() };
        let cipher_count = unsafe { ssl::SSL_GetNumImplementedCiphers() } as usize;
        for i in 0..cipher_count {
            let p = all_ciphers.wrapping_add(i);
            let rv = unsafe { ssl::SSL_CipherPrefSet(self.fd, *p as i32, false as ssl::PRBool) };
            result::result(rv)?;
        }

        for c in ciphers {
            let rv = unsafe { ssl::SSL_CipherPrefSet(self.fd, *c as i32, true as ssl::PRBool) };
            result::result(rv)?;
        }
        Ok(())
    }

    pub fn set_groups(&mut self, groups: &[Group]) -> Res<()> {
        // SSLNamedGroup is a different size to Group, so copy one by one.
        let group_vec: Vec<_> = groups
            .iter()
            .map(|&g| g as ssl::SSLNamedGroup::Type)
            .collect();

        let ptr = group_vec.as_slice().as_ptr();
        let rv = unsafe { ssl::SSL_NamedGroupConfig(self.fd, ptr, group_vec.len() as c_uint) };
        result::result(rv)
    }

    pub fn set_option(&mut self, opt: ssl::Opt, value: bool) -> Res<()> {
        result::result(unsafe { ssl::SSL_OptionSet(self.fd, opt.as_int(), opt.map_enabled(value)) })
    }

    /// set_alpn sets a list of preferred protocols, starting with the most preferred.
    /// Though ALPN [RFC7301] permits octet sequences, this only allows for UTF-8-encoded
    /// strings.
    ///
    /// This asserts if no items are provided, or if any individual item is longer than
    /// 255 octets in length.
    pub fn set_alpn<A: ToString, I: IntoIterator<Item = A>>(&mut self, protocols: I) -> Res<()> {
        // Validate and set length.
        // Unfortunately, this means that we need to run the iterator twice.
        let alpn: Vec<String> = protocols.into_iter().map(|v| v.to_string()).collect();
        let mut encoded_len = alpn.len();
        for v in alpn.iter() {
            assert!(v.len() < 256);
            encoded_len += v.len();
        }

        // Prepare to encode.
        let mut encoded = Vec::with_capacity(encoded_len);
        let mut cursor = 0usize;
        let mut add = |v: String| {
            encoded.push(v.len() as u8);
            cursor += 1;
            encoded.extend_from_slice(v.as_bytes());
            cursor += v.len();
        };

        // NSS inherited an idiosyncratic API as a result of having implemented NPN
        // before ALPN.  For that reason, we need to put the "best" option last.
        let mut alpn_i = alpn.into_iter();
        let best = alpn_i
            .next()
            .expect("at least one ALPN value needs to be provided");
        for v in alpn_i {
            add(v);
        }
        add(best);
        assert_eq!(encoded_len, encoded.len());

        // Now give the result to NSS.
        let rv = unsafe {
            ssl::SSL_SetNextProtoNego(
                self.fd,
                encoded.as_slice().as_ptr(),
                encoded.len() as c_uint,
            )
        };
        result::result(rv)
    }

    // Common configuration.
    pub fn configure(&mut self) -> Res<()> {
        self.set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)?;
        self.set_option(ssl::Opt::Locking, false)?;
        self.set_option(ssl::Opt::Tickets, false)?;
        Ok(())
    }

    fn set_raw(&mut self, r: bool) -> Res<()> {
        if self.raw.is_none() {
            self.secrets.register(self.fd)?;
            self.raw = Some(r);
            Ok(())
        } else if self.raw.unwrap() == r {
            Ok(())
        } else {
            Err(Error::MixedHandshakeMethod)
        }
    }

    // TODO(mt) consider whether this info should instead be attached
    // to the Completed state.
    pub fn info(&self) -> Option<&SecretAgentInfo> {
        self.inf.as_ref()
    }

    pub fn preinfo(&self) -> Res<SecretAgentPreInfo> {
        SecretAgentPreInfo::new(self.fd)
    }

    /// Call this function to mark the peer as authenticated.
    /// Only call this function if handshake/handshake_raw returns
    /// HandshakeState::AuthenticationPending, or it will panic.
    pub fn authenticated(&mut self) {
        assert_eq!(self.st, HandshakeState::AuthenticationPending);
        *self.auth_required = false;
        self.st = HandshakeState::Authenticated;
    }

    fn update_state(&mut self, rv: ssl::SECStatus) -> Res<()> {
        self.st = match result::result_or_blocked(rv)? {
            true => match *self.auth_required {
                true => HandshakeState::AuthenticationPending,
                false => HandshakeState::InProgress,
            },
            false => {
                self.inf = Some(SecretAgentInfo::new(self.fd)?);
                HandshakeState::Complete
            }
        };
        println!("{:?} state = {:?}", self.fd, &self.st);
        Ok(())
    }

    fn set_failed(&mut self) -> Error {
        let e = result::result(ssl::SECFailure).unwrap_err();
        self.st = HandshakeState::Failed(e.clone());
        return e;
    }

    // Drive the TLS handshake, taking bytes from @input and putting
    // any bytes necessary into @output.
    // This takes the current time as @now.
    // On success a tuple of a HandshakeState and usize indicate whether the handshake
    // is complete and how many bytes were written to @output, respectively.
    // If the state is HandshakeState::AuthenticationPending, then ONLY call this
    // function if you want to proceed, because this will mark the certificate as OK.
    pub fn handshake(&mut self, _now: u64, input: &[u8]) -> Res<(HandshakeState, Vec<u8>)> {
        self.set_raw(false)?;

        let rv = {
            // Within this scope, _h maintains a mutable reference to self.io.
            let _h = self.io.wrap(input);
            match self.st {
                HandshakeState::Authenticated => unsafe {
                    ssl::SSL_AuthCertificateComplete(self.fd, 0)
                },
                _ => unsafe { ssl::SSL_ForceHandshake(self.fd) },
            }
        };
        // Take before updating state so that we leave the output buffer empty
        // even if there is an error.
        let output = self.io.take_output();
        self.update_state(rv)?;
        Ok((self.st.clone(), output))
    }

    // Drive the TLS handshake, but get the raw content of records, not
    // protected records as bytes. This function is incompatible with
    // handshake(); use either this or handshake() exclusively.
    //
    // Ideally, this only includes records from the current epoch.
    // If you send data from multiple epochs, you might end up being sad.
    pub fn handshake_raw(
        &mut self,
        _now: u64,
        input: Option<Record>,
    ) -> Res<(HandshakeState, RecordList)> {
        self.set_raw(true)?;

        // Setup for accepting records.
        let mut records: Box<RecordList> = Default::default();
        let records_ptr = &mut *records as *mut RecordList as *mut c_void;
        let rv =
            unsafe { ssl::SSL_RecordLayerWriteCallback(self.fd, Some(ingest_record), records_ptr) };
        if rv != ssl::SECSuccess {
            return Err(self.set_failed());
        }

        // Fire off any authentication we might need to complete.
        if self.st == HandshakeState::Authenticated {
            let rv = unsafe { ssl::SSL_AuthCertificateComplete(self.fd, 0) };
            println!("SSL_AuthCertificateComplete: {:?}", rv);
            self.update_state(rv)?;
            if self.st == HandshakeState::Complete {
                return Ok((self.st.clone(), *records));
            }
        }

        // Feed in any records.
        if let Some(rec) = input {
            let res = emit_record(self.fd, rec);
            if let Err(_) = res {
                return Err(self.set_failed());
            }
        }

        // Drive the handshake once more.
        let rv = unsafe { ssl::SSL_ForceHandshake(self.fd) };
        self.update_state(rv)?;

        Ok((self.st.clone(), *records))
    }

    // State returns the status of the handshake.
    pub fn state(&self) -> &HandshakeState {
        &self.st
    }

    pub fn read_secret(&self, epoch: Epoch) -> Option<&p11::SymKey> {
        self.secrets.read().get(epoch)
    }

    pub fn write_secret(&self, epoch: Epoch) -> Option<&p11::SymKey> {
        self.secrets.write().get(epoch)
    }
}

// A TLS Client.
#[derive(Debug)]
pub struct Client {
    agent: SecretAgent,
}

impl Client {
    pub fn new(server_name: &str) -> Res<Self> {
        let mut agent = SecretAgent::new()?;
        let url = CString::new(server_name.to_string());
        if url.is_err() {
            return Err(Error::InternalError);
        }
        result::result(unsafe { ssl::SSL_SetURL(agent.fd, url.unwrap().as_ptr()) })?;
        agent.ready(false)?;
        Ok(Client { agent })
    }
}

impl Deref for Client {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        &self.agent
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        &mut self.agent
    }
}

#[derive(Debug)]
pub struct Server {
    agent: SecretAgent,
}

impl Server {
    pub fn new<A: ToString, I: IntoIterator<Item = A>>(certificates: I) -> Res<Self> {
        let mut agent = SecretAgent::new()?;

        for n in certificates {
            let c = CString::new(n.to_string());
            if c.is_err() {
                return Err(Error::CertificateLoading);
            }
            let c = c.unwrap();
            let cert = match NonNull::new(unsafe {
                p11::PK11_FindCertFromNickname(c.as_ptr(), null_mut())
            }) {
                None => return Err(Error::CertificateLoading),
                Some(ptr) => p11::Certificate::new(ptr),
            };
            let key = match NonNull::new(unsafe {
                p11::PK11_FindKeyByAnyCert(*cert.deref(), null_mut())
            }) {
                None => return Err(Error::CertificateLoading),
                Some(ptr) => p11::PrivateKey::new(ptr),
            };
            result::result(unsafe {
                ssl::SSL_ConfigServerCert(agent.fd, *cert.deref(), *key.deref(), null(), 0)
            })?;
        }

        agent.ready(true)?;
        Ok(Server { agent })
    }
}

impl Deref for Server {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        &self.agent
    }
}

impl DerefMut for Server {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        &mut self.agent
    }
}

/// A generic container for Client or Server.
#[derive(Debug)]
pub enum Agent {
    Client(crate::agent::Client),
    Server(crate::agent::Server),
}

impl Deref for Agent {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        match self {
            Agent::Client(c) => c.deref(),
            Agent::Server(s) => s.deref(),
        }
    }
}

impl DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        match self {
            Agent::Client(c) => c.deref_mut(),
            Agent::Server(s) => s.deref_mut(),
        }
    }
}
