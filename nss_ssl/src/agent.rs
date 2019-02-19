pub use crate::agentio::SslRecordList;
use crate::agentio::{AgentIo, METHODS};
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
use std::ptr::{null, null_mut};

#[derive(Clone, Debug, PartialEq)]
pub enum HandshakeState {
    New,
    InProgress,
    AuthenticationPending,
    Complete,
    Failed(Error),
}

// Agent holds the common parts of client and server.
pub struct Agent {
    fd: *mut ssl::PRFileDesc,
    io: Box<AgentIo>,
    st: HandshakeState,
    auth_required: Box<bool>,
}

impl Agent {
    fn new() -> Res<Agent> {
        let mut agent = Agent {
            fd: null_mut(),
            io: Box::new(AgentIo::new()),
            st: HandshakeState::New,
            auth_required: Box::new(false),
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
                Some(Agent::auth_complete_hook),
                &mut *self.auth_required as *mut bool as *mut c_void,
            )
        })?;
        self.configure()?;
        result::result(unsafe { ssl::SSL_ResetHandshake(self.fd, is_server as ssl::PRBool) })
    }

    pub fn set_version_range(&self, min: u16, max: u16) -> Res<()> {
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
        self.set_version_range(ssl::TLS_VERSION_1_3, ssl::TLS_VERSION_1_3)?;
        self.set_option(ssl::Opt::Locking, false)?;
        self.set_option(ssl::Opt::Tickets, false)?;
        Ok(())
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
        let (_h, out) = self.io.wrap(input, output);
        let rv = match *self.auth_required {
            true => {
                *self.auth_required = false;
                unsafe { ssl::SSL_AuthCertificateComplete(self.fd, 0) }
            }
            _ => unsafe { ssl::SSL_ForceHandshake(self.fd) },
        };
        self.st = match result::result_or_blocked(rv)? {
            true => match *self.auth_required {
                true => HandshakeState::AuthenticationPending,
                false => HandshakeState::InProgress,
            },
            false => HandshakeState::Complete,
        };
        Ok((self.st.clone(), out.written()))
    }

    // Drive the TLS handshake, but get the raw content of records, not
    // protected records as bytes. This function is incompatible with
    // handshake(); use either this or handshake() exclusively.
    // fn handshake_raw<'a, 'b>(&mut self,
    //     _now: &std::time::SystemTime,
    //     input: SslRecord<'b>,
    //     output: &'a mut [u8],
    // ) -> Res<(HandshakeState, SslRecordList<'a>)>;

    // State returns the status of the handshake.
    pub fn state(&self) -> &HandshakeState {
        &self.st
    }
}

// A TLS Client.
pub struct Client {
    agent: Agent,
}

impl Client {
    pub fn new(server_name: &str) -> Res<Self> {
        let mut agent = Agent::new()?;
        let url = CString::new(server_name.to_string());
        if url.is_err() {
            return Err(Error::UnexpectedError);
        }
        result::result(unsafe { ssl::SSL_SetURL(agent.fd, url.unwrap().as_ptr()) })?;
        agent.ready(false)?;
        Ok(Client { agent })
    }
}

impl Deref for Client {
    type Target = Agent;
    fn deref(&self) -> &Agent {
        &self.agent
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }
}

pub struct Server {
    agent: Agent,
}

impl Server {
    pub fn new<T>(certificates: T) -> Res<Self>
    where
        T: IntoIterator,
        T::Item: ToString,
    {
        let mut agent = Agent::new()?;

        for n in certificates {
            let c = CString::new(n.to_string());
            if c.is_err() {
                return Err(Error::CertificateLoading);
            }
            let c = c.unwrap();
            let cert = p11::ScopedCertificate(unsafe {
                p11::PK11_FindCertFromNickname(c.as_ptr(), null_mut())
            });
            if cert.is_null() {
                return Err(Error::CertificateLoading);
            }
            let key = p11::ScopedPrivateKey(unsafe {
                p11::PK11_FindKeyByAnyCert(*cert.deref(), null_mut())
            });
            if key.is_null() {
                return Err(Error::CertificateLoading);
            }
            result::result(unsafe {
                ssl::SSL_ConfigServerCert(agent.fd, *cert.deref(), *key.deref(), null(), 0)
            })?;
        }

        agent.ready(true)?;
        Ok(Server { agent })
    }
}


impl Deref for Server {
    type Target = Agent;
    fn deref(&self) -> &Agent {
        &self.agent
    }
}

impl DerefMut for Server {
    fn deref_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }
}