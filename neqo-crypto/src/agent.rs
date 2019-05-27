// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::agentio::{emit_record, ingest_record, AgentIo, METHODS};
pub use crate::agentio::{Record, RecordList};
pub use crate::cert::CertificateChain;
use crate::constants::*;
use crate::err::{Error, Res};
use crate::ext::{ExtensionHandler, ExtensionTracker};
use crate::initialized;
use crate::p11;
use crate::prio;
use crate::result;
use crate::secrets::SecretHolder;
use crate::ssl;

use neqo_common::{qdebug, qinfo, qwarn};
use std::cell::RefCell;
use std::ffi::CString;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_uint, c_void};
use std::ptr::{null, null_mut, NonNull};
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq)]
pub enum HandshakeState {
    New,
    InProgress,
    AuthenticationPending,
    Authenticated,
    Complete(SecretAgentInfo),
    Failed(Error),
}

impl HandshakeState {
    pub fn connected(&self) -> bool {
        match self {
            HandshakeState::Complete(_) => true,
            _ => false,
        }
    }
}

fn get_alpn(fd: *mut ssl::PRFileDesc, pre: bool) -> Res<Option<String>> {
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

    let alpn = match (pre, alpn_state) {
        (true, ssl::SSLNextProtoState::SSL_NEXT_PROTO_EARLY_VALUE)
        | (false, ssl::SSLNextProtoState::SSL_NEXT_PROTO_NEGOTIATED)
        | (false, ssl::SSLNextProtoState::SSL_NEXT_PROTO_SELECTED) => {
            chosen.truncate(chosen_len as usize);
            Some(match String::from_utf8(chosen) {
                Ok(a) => a,
                _ => return Err(Error::InternalError),
            })
        }
        _ => None,
    };
    qinfo!([format!("{:p}", fd)] "got ALPN {:?}", alpn);
    Ok(alpn)
}

pub struct SecretAgentPreInfo {
    info: ssl::SSLPreliminaryChannelInfo,
    alpn: Option<String>,
}

macro_rules! preinfo_arg {
    ($v:ident, $m:ident, $f:ident: $t:ident $(,)?) => {
        pub fn $v(&self) -> Option<$t> {
            match self.info.valuesSet & ssl::$m {
                0 => None,
                _ => Some(self.info.$f as $t)
            }
        }
    };
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

        Ok(SecretAgentPreInfo {
            info,
            alpn: get_alpn(fd, true)?,
        })
    }

    preinfo_arg!(version, ssl_preinfo_version, protocolVersion: Version);
    preinfo_arg!(cipher_suite, ssl_preinfo_cipher_suite, cipherSuite: Cipher);

    pub fn early_data(&self) -> bool {
        self.info.canSendEarlyData != 0
    }

    pub fn max_early_data(&self) -> usize {
        self.info.maxEarlyDataSize as usize
    }

    pub fn alpn(&self) -> Option<&String> {
        self.alpn.as_ref()
    }

    preinfo_arg!(
        early_data_cipher,
        ssl_preinfo_0rtt_cipher_suite,
        zeroRttCipherSuite: Cipher,
    );
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SecretAgentInfo {
    version: Version,
    cipher: Cipher,
    group: Group,
    resumed: bool,
    early_data: bool,
    alpn: Option<String>,
}

impl SecretAgentInfo {
    fn new(fd: *mut ssl::PRFileDesc) -> Res<SecretAgentInfo> {
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
            version: info.protocolVersion as Version,
            cipher: info.cipherSuite as Cipher,
            group: info.keaGroup as Group,
            resumed: info.resumed != 0,
            early_data: info.earlyDataAccepted != 0,
            alpn: get_alpn(fd, false)?,
        })
    }

    pub fn version(&self) -> Version {
        self.version
    }
    pub fn cipher_suite(&self) -> Cipher {
        self.cipher
    }
    pub fn key_exchange(&self) -> Group {
        self.group
    }
    pub fn resumed(&self) -> bool {
        self.resumed
    }
    pub fn early_data_accepted(&self) -> bool {
        self.early_data
    }
    pub fn alpn(&self) -> Option<&String> {
        self.alpn.as_ref()
    }
}

/// SecretAgent holds the common parts of client and server.
#[derive(Debug)]
pub struct SecretAgent {
    fd: *mut ssl::PRFileDesc,
    secrets: SecretHolder,
    raw: Option<bool>,
    io: Box<AgentIo>,
    state: HandshakeState,

    /// Records whether authentication of certificates is required.
    auth_required: Box<bool>,
    /// Records any fatal alert that is sent by the stack.
    alert: Box<Option<Alert>>,
    /// Records the last resumption token.
    resumption: Box<Option<Vec<u8>>>,

    extension_handlers: Vec<ExtensionTracker>,
    inf: Option<SecretAgentInfo>,
}

impl SecretAgent {
    fn new() -> Res<SecretAgent> {
        let mut agent = SecretAgent {
            fd: null_mut(),
            secrets: Default::default(),
            raw: None,
            io: Box::new(AgentIo::new()),
            state: HandshakeState::New,

            auth_required: Box::new(false),
            alert: Box::new(None),
            resumption: Box::new(None),

            extension_handlers: Default::default(),
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
        ssl::_SECStatus_SECWouldBlock
    }

    unsafe extern "C" fn alert_sent_cb(
        fd: *const ssl::PRFileDesc,
        arg: *mut c_void,
        alert: *const ssl::SSLAlert,
    ) {
        let alert = alert.as_ref().unwrap();
        if alert.level == 2 {
            // Fatal alerts demand attention.
            let p = arg as *mut Option<Alert>;
            let st = p.as_mut().unwrap();
            match st {
                None => {
                    *st = Some(alert.description);
                }
                _ => {
                    qwarn!([format!("{:p}", fd)] "duplicate alert {}", alert.description);
                }
            }
        }
    }

    unsafe extern "C" fn resumption_token_cb(
        _fd: *mut ssl::PRFileDesc,
        token: *const u8,
        len: c_uint,
        arg: *mut c_void,
    ) -> ssl::SECStatus {
        let resumption_ptr = arg as *mut Option<Vec<u8>>;
        let resumption = resumption_ptr.as_mut().unwrap();
        let mut v = Vec::with_capacity(len as usize);
        v.extend_from_slice(std::slice::from_raw_parts(token, len as usize));
        *resumption = Some(v);
        ssl::SECSuccess
    }

    // Ready this for connecting.
    fn ready(&mut self, is_server: bool) -> Res<()> {
        let rv = unsafe {
            ssl::SSL_AuthCertificateHook(
                self.fd,
                Some(SecretAgent::auth_complete_hook),
                &mut *self.auth_required as *mut bool as *mut c_void,
            )
        };
        result::result(rv)?;

        let rv = unsafe {
            ssl::SSL_AlertSentCallback(
                self.fd,
                Some(SecretAgent::alert_sent_cb),
                &mut *self.alert as *mut Option<Alert> as *mut c_void,
            )
        };
        result::result(rv)?;

        let rv = unsafe {
            ssl::SSL_SetResumptionTokenCallback(
                self.fd,
                Some(SecretAgent::resumption_token_cb),
                &mut *self.resumption as *mut Option<Vec<u8>> as *mut c_void,
            )
        };
        result::result(rv)?;

        self.configure()?;
        result::result(unsafe { ssl::SSL_ResetHandshake(self.fd, is_server as ssl::PRBool) })
    }

    /// Default configuration.
    fn configure(&mut self) -> Res<()> {
        self.set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)?;
        self.set_option(ssl::Opt::Locking, false)?;
        self.set_option(ssl::Opt::Tickets, false)?;
        Ok(())
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
            let rv =
                unsafe { ssl::SSL_CipherPrefSet(self.fd, i32::from(*p), false as ssl::PRBool) };
            result::result(rv)?;
        }

        for c in ciphers {
            let rv = unsafe { ssl::SSL_CipherPrefSet(self.fd, i32::from(*c), true as ssl::PRBool) };
            result::result(rv)?;
        }
        Ok(())
    }

    pub fn set_groups(&mut self, groups: &[Group]) -> Res<()> {
        // SSLNamedGroup is a different size to Group, so copy one by one.
        let group_vec: Vec<_> = groups.iter().map(|&g| SSLNamedGroup::from(g)).collect();

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
        let mut add = |v: String| {
            encoded.push(v.len() as u8);
            encoded.extend_from_slice(v.as_bytes());
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

    /// Install an extension handler.
    ///
    /// This can be called multiple times with different values for `ext`.  The handler is provided as
    /// Rc<RefCell<>> so that the caller is able to hold a reference to the handler and later access any
    /// state that it accumulates.
    pub fn extension_handler(
        &mut self,
        ext: Extension,
        handler: Rc<RefCell<dyn ExtensionHandler>>,
    ) -> Res<()> {
        let tracker = ExtensionTracker::new(self.fd, ext, handler)?;
        self.extension_handlers.push(tracker);
        Ok(())
    }

    // This function tracks whether handshake() or handshake_raw() was used
    // and prevents the other from being used.
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

    /// Get information about the connection.
    /// This includes the version, ciphersuite, and ALPN.
    ///
    /// Calling this function returns None until the connection is complete.
    pub fn info(&self) -> Option<&SecretAgentInfo> {
        match self.state {
            HandshakeState::Complete(ref info) => Some(info),
            _ => None,
        }
    }

    /// Get any preliminary information about the status of the connection.
    ///
    /// This includes whether 0-RTT was accepted and any information related to that.
    /// Calling this function collects all the relevant information.
    pub fn preinfo(&self) -> Res<SecretAgentPreInfo> {
        SecretAgentPreInfo::new(self.fd)
    }

    /// Get the peer's certificate chain.
    pub fn peer_certificate(&self) -> Option<CertificateChain> {
        CertificateChain::new(self.fd)
    }

    /// Return the resumption token.
    pub fn resumption_token(&self) -> Option<&Vec<u8>> {
        (*self.resumption).as_ref()
    }

    /// Enable resumption, using a token previously provided.
    pub fn set_resumption_token(&mut self, token: &[u8]) -> Res<()> {
        let rv =
            unsafe { ssl::SSL_SetResumptionToken(self.fd, token.as_ptr(), token.len() as c_uint) };
        result::result(rv)
    }

    /// Return any fatal alert that the TLS stack might have sent.
    pub fn alert(&self) -> &Option<Alert> {
        &*self.alert
    }

    /// Call this function to mark the peer as authenticated.
    /// Only call this function if handshake/handshake_raw returns
    /// HandshakeState::AuthenticationPending, or it will panic.
    pub fn authenticated(&mut self) {
        assert_eq!(self.state, HandshakeState::AuthenticationPending);
        *self.auth_required = false;
        self.state = HandshakeState::Authenticated;
    }

    fn capture_error<T>(&mut self, res: Res<T>) -> Res<T> {
        if let Err(e) = &res {
            qwarn!([self] "error: {:?}", e);
            self.state = HandshakeState::Failed(e.clone());
        }
        res
    }

    fn update_state(&mut self, rv: ssl::SECStatus) -> Res<()> {
        let res = self.capture_error(result::result_or_blocked(rv))?;
        self.state = match res {
            true => match *self.auth_required {
                true => HandshakeState::AuthenticationPending,
                false => HandshakeState::InProgress,
            },
            false => {
                let info = self.capture_error(SecretAgentInfo::new(self.fd))?;
                HandshakeState::Complete(info)
            }
        };
        qinfo!([self] "state -> {:?}", self.state);
        Ok(())
    }

    fn set_failed(&mut self) -> Error {
        self.capture_error(result::result(ssl::SECFailure))
            .unwrap_err()
    }

    // Drive the TLS handshake, taking bytes from @input and putting
    // any bytes necessary into @output.
    // This takes the current time as @now.
    // On success a tuple of a HandshakeState and usize indicate whether the handshake
    // is complete and how many bytes were written to @output, respectively.
    // If the state is HandshakeState::AuthenticationPending, then ONLY call this
    // function if you want to proceed, because this will mark the certificate as OK.
    pub fn handshake(&mut self, _now: u64, input: &[u8]) -> Res<Vec<u8>> {
        self.set_raw(false)?;

        let rv = {
            // Within this scope, _h maintains a mutable reference to self.io.
            let _h = self.io.wrap(input);
            match self.state {
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
        Ok(output)
    }

    /// Setup to receive records for raw handshake functions.
    fn setup_raw(&mut self) -> Res<Box<RecordList>> {
        self.set_raw(true)?;

        // Setup for accepting records.
        let mut records: Box<RecordList> = Default::default();
        let records_ptr = &mut *records as *mut RecordList as *mut c_void;
        let rv =
            unsafe { ssl::SSL_RecordLayerWriteCallback(self.fd, Some(ingest_record), records_ptr) };
        if rv != ssl::SECSuccess {
            return Err(self.set_failed());
        }

        Ok(records)
    }

    // Drive the TLS handshake, but get the raw content of records, not
    // protected records as bytes. This function is incompatible with
    // handshake(); use either this or handshake() exclusively.
    //
    // Ideally, this only includes records from the current epoch.
    // If you send data from multiple epochs, you might end up being sad.
    pub fn handshake_raw(&mut self, _now: u64, input: Option<Record>) -> Res<RecordList> {
        let records = self.setup_raw()?;

        // Fire off any authentication we might need to complete.
        if self.state == HandshakeState::Authenticated {
            let rv = unsafe { ssl::SSL_AuthCertificateComplete(self.fd, 0) };
            qdebug!([self] "SSL_AuthCertificateComplete: {:?}", rv);
            // This should return SECSuccess, so don't use update_state().
            self.capture_error(result::result(rv))?;
        }

        // Feed in any records.
        if let Some(rec) = input {
            let res = emit_record(self.fd, rec);
            if res.is_err() {
                return Err(self.set_failed());
            }
        }

        // Drive the handshake once more.
        let rv = unsafe { ssl::SSL_ForceHandshake(self.fd) };
        self.update_state(rv)?;

        Ok(*records)
    }

    pub fn send_session_ticket(&mut self, extra: &[u8]) -> Res<RecordList> {
        let records = self.setup_raw()?;

        let rv =
            unsafe { ssl::SSL_SendSessionTicket(self.fd, extra.as_ptr(), extra.len() as c_uint) };
        result::result(rv)?;

        Ok(*records)
    }

    // State returns the status of the handshake.
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    pub fn read_secret(&self, epoch: Epoch) -> Option<&p11::SymKey> {
        self.secrets.read().get(epoch)
    }

    pub fn write_secret(&self, epoch: Epoch) -> Option<&p11::SymKey> {
        self.secrets.write().get(epoch)
    }
}

impl ::std::fmt::Display for SecretAgent {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Agent {:p}", self.fd)
    }
}

/// A TLS Client.
#[derive(Debug)]
pub struct Client {
    agent: SecretAgent,
}

impl Client {
    pub fn new<S: ToString>(server_name: S) -> Res<Self> {
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

impl From<Client> for Agent {
    fn from(c: Client) -> Self {
        Agent::Client(c)
    }
}

impl From<Server> for Agent {
    fn from(s: Server) -> Self {
        Agent::Server(s)
    }
}
