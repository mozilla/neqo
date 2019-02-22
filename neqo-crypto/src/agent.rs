use crate::agentio::{emit_records, ingest_record, AgentIo, METHODS};
pub use crate::agentio::{SslRecord, SslRecordList};
use crate::constants::*;
use crate::err::{Error, Res};
use crate::initialized;
use crate::p11;
use crate::prio;
use crate::result;
use crate::ssl;

use std::ffi::CString;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_void;
use std::ptr::{null, null_mut, NonNull};

#[derive(Clone, Debug, PartialEq)]
pub enum HandshakeState {
    New,
    InProgress,
    AuthenticationPending,
    Complete,
    Failed(Error),
}

#[derive(Debug, Default)]
pub struct SecretAgentInfo {
    ver: Version,
    cipher: Cipher,
    early_data: bool,
}

impl SecretAgentInfo {
    fn update(&mut self, fd: *mut ssl::PRFileDesc) -> Res<()> {
        let mut info: ssl::SSLChannelInfo = unsafe { mem::uninitialized() };
        let rv = unsafe {
            ssl::SSL_GetChannelInfo(
                fd,
                &mut info,
                mem::size_of::<ssl::SSLChannelInfo>() as ssl::PRUint32,
            )
        };
        result::result(rv)?;
        self.ver = info.protocolVersion as Version;
        self.cipher = info.cipherSuite as Cipher;
        self.early_data = info.earlyDataAccepted != 0;
        Ok(())
    }

    pub fn version(&self) -> Version {
        self.ver
    }
    pub fn cipher_suite(&self) -> Cipher {
        self.cipher
    }
    pub fn early_data_accepted(&self) -> bool {
        self.early_data
    }
}

// SecretAgent holds the common parts of client and server.
#[derive(Debug)]
pub struct SecretAgent {
    fd: *mut ssl::PRFileDesc,
    raw: Option<bool>,
    io: Box<AgentIo>,
    st: HandshakeState,
    auth_required: Box<bool>,

    inf: SecretAgentInfo,
}

impl SecretAgent {
    fn new() -> Res<SecretAgent> {
        let mut agent = SecretAgent {
            fd: null_mut(),
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

    pub fn set_version_range(&self, min: Version, max: Version) -> Res<()> {
        let range = ssl::SSLVersionRange {
            min: min as ssl::PRUint16,
            max: max as ssl::PRUint16,
        };
        result::result(unsafe { ssl::SSL_VersionRangeSet(self.fd, &range) })
    }

    pub fn set_option(&self, opt: ssl::Opt, value: bool) -> Res<()> {
        result::result(unsafe { ssl::SSL_OptionSet(self.fd, opt.as_int(), opt.map_enabled(value)) })
    }

    // Common configuration.
    pub fn configure(&self) -> Res<()> {
        self.set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)?;
        self.set_option(ssl::Opt::Locking, false)?;
        self.set_option(ssl::Opt::Tickets, false)?;
        Ok(())
    }

    fn set_raw(&mut self, r: bool) -> Res<()> {
        if self.raw.is_none() {
            self.raw = Some(r);
            Ok(())
        } else if self.raw.unwrap() == r {
            Ok(())
        } else {
            Err(Error::MixedHandshakeMethod)
        }
    }

    pub fn info(&self) -> &SecretAgentInfo {
        &self.inf
    }

    fn update_state(&mut self, rv: ssl::SECStatus) -> Res<()> {
        self.st = match result::result_or_blocked(rv)? {
            true => match *self.auth_required {
                true => HandshakeState::AuthenticationPending,
                false => HandshakeState::InProgress,
            },
            false => {
                self.inf.update(self.fd)?;
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
    pub fn handshake(
        &mut self,
        _now: &std::time::SystemTime,
        input: &[u8],
        output: &mut [u8],
    ) -> Res<(HandshakeState, usize)> {
        self.set_raw(false)?;

        let (rv, written) = {
            // Within this scope, _h maintains a mutable reference to self.io.
            let (_h, out) = self.io.wrap(input, output);
            (
                match *self.auth_required {
                    true => {
                        *self.auth_required = false;
                        unsafe { ssl::SSL_AuthCertificateComplete(self.fd, 0) }
                    }
                    _ => unsafe { ssl::SSL_ForceHandshake(self.fd) },
                },
                out.len(),
            )
        };
        self.update_state(rv)?;
        Ok((self.st.clone(), written))
    }

    // Drive the TLS handshake, but get the raw content of records, not
    // protected records as bytes. This function is incompatible with
    // handshake(); use either this or handshake() exclusively.
    //
    // Ideally, this only includes records from the current epoch.
    // If you send data from multiple epochs, you might end up being sad.
    pub fn handshake_raw<'a, 'b>(
        &mut self,
        _now: &std::time::SystemTime, // TODO(mt) : u64
        input: SslRecordList<'b>,     // TODO(mt) : just take one record
        output: &'a mut [u8],
    ) -> Res<(HandshakeState, SslRecordList<'a>)> {
        self.set_raw(true)?;

        // Setup for accepting records.
        let mut records = Box::new(SslRecordList::new(output));
        let records_ptr = &mut *records as *mut SslRecordList as *mut c_void;
        let rv =
            unsafe { ssl::SSL_RecordLayerWriteCallback(self.fd, Some(ingest_record), records_ptr) };
        if rv != ssl::SECSuccess {
            return Err(self.set_failed());
        }

        // Fire off any authentication we might need to complete.
        if *self.auth_required {
            *self.auth_required = false;
            let rv = unsafe { ssl::SSL_AuthCertificateComplete(self.fd, 0) };
            println!("SSL_AuthCertificateComplete: {:?}", rv);
            self.update_state(rv)?;
            if self.st == HandshakeState::Complete {
                return Ok((self.st.clone(), *records));
            }
        }

        // Feed in any records.
        let res = emit_records(self.fd, input);
        if let Err(_) = res {
            return Err(self.set_failed());
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
    pub fn new<T>(certificates: T) -> Res<Self>
    where
        T: IntoIterator,
        T::Item: ToString,
    {
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
