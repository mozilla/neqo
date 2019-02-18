use crate::agentio::{AgentIo, METHODS};
use crate::err::{Error, Res};
use crate::initialized;
use crate::p11;
use crate::prio;
use crate::result;
use crate::ssl;

use std::borrow::BorrowMut;
use std::clone::Clone;
use std::ffi::CString;
use std::mem;
use std::ops::Deref;
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

pub trait Agent {
    fn fd(&self) -> *mut ssl::PRFileDesc;

    fn set_version_range(&self, min: u16, max: u16) -> Res<()> {
        let range = ssl::SSLVersionRange {
            min: min as ssl::PRUint16,
            max: max as ssl::PRUint16,
        };
        result::result(unsafe { ssl::SSL_VersionRangeSet(self.fd(), &range) })
    }

    fn set_option(&self, opt: ssl::Opt, value: bool) -> Res<()> {
        result::result(unsafe {
            ssl::SSL_OptionSet(self.fd(), opt.as_int(), opt.map_enabled(value))
        })
    }

    // Common configuration.
    fn configure(&self) -> Res<()> {
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
    fn handshake(
        &mut self,
        _now: &std::time::SystemTime,
        input: &[u8],
        output: &mut [u8],
    ) -> Res<(HandshakeState, usize)>;

    // State returns the status of the handshake.
    fn state(&self) -> &HandshakeState;
}

// Create a new SSL file descriptor.
//
// Note that we create separate bindings for PRFileDesc as both
// ssl::PRFileDesc and prio::PRFileDesc.  This keeps the bindings
// minimal, but it means that the two forms need casts to translate
// between them.  ssl::PRFileDesc is left as an opaque type, as the
// ssl::SSL_* APIs only need an opaque type.
fn create_fd(io: *mut AgentIo) -> Res<*mut ssl::PRFileDesc> {
    assert!(initialized());

    let label = CString::new("sslwrapper").expect("cstring failed");
    let id = unsafe { prio::PR_GetUniqueIdentity(label.as_ptr()) };

    let base_fd = unsafe { prio::PR_CreateIOLayerStub(id, METHODS) };
    if base_fd.is_null() {
        return Err(Error::CreateSslSocket);
    }
    let fd = unsafe {
        (*base_fd).secret = mem::transmute(io);
        ssl::SSL_ImportFD(null_mut(), base_fd as *mut ssl::PRFileDesc)
    };
    if fd.is_null() {
        return Err(Error::CreateSslSocket);
    }
    mem::forget(base_fd); // Free the base.
    Ok(fd)
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

// Ready a new Agent instance.
fn ready_agent(agent: &Agent, is_server: bool, auth_required_ptr: *mut bool) -> Res<()> {
    result::result(unsafe {
        ssl::SSL_AuthCertificateHook(
            agent.fd(),
            Some(auth_complete_hook),
            auth_required_ptr as *mut c_void,
        )
    })?;
    result::result(unsafe { ssl::SSL_ResetHandshake(agent.fd(), is_server as ssl::PRBool) })
}

fn handshake(
    fd: *mut ssl::PRFileDesc,
    io: &mut AgentIo,
    auth_required: &mut Box<bool>,
    _now: &std::time::SystemTime,
    input: &[u8],
    output: &mut [u8],
) -> Res<(HandshakeState, usize)> {
    let written = io.setup(input, output);
    let needs_auth: bool = **auth_required;
    let rv = match needs_auth {
        true => {
            **auth_required = false;
            unsafe { ssl::SSL_AuthCertificateComplete(fd, 0) }
        }
        _ => unsafe { ssl::SSL_ForceHandshake(fd) },
    };
    let state = match result::result_or_blocked(rv)? {
        true => match **auth_required {
            true => HandshakeState::AuthenticationPending,
            false => HandshakeState::InProgress,
        },
        false => HandshakeState::Complete,
    };
    Ok((state, written.into()))
}

// A TLS Client.
pub struct Client {
    fd: *mut ssl::PRFileDesc,
    io: Box<AgentIo>,
    st: HandshakeState,
    auth_required: Box<bool>,
}

impl Client {
    pub fn new(server_name: &str) -> Res<Self> {
        let io = Box::into_raw(Box::new(AgentIo::new()));
        let ar = Box::into_raw(Box::new(false));
        let client = Client {
            fd: create_fd(io)?,
            io: unsafe { Box::from_raw(io) }, // take ownership
            st: HandshakeState::New,
            auth_required: unsafe { Box::from_raw(ar) }, // take ownership
        };
        let url = CString::new(server_name.to_string());
        if url.is_err() {
            return Err(Error::UnexpectedError);
        }
        result::result(unsafe { ssl::SSL_SetURL(client.fd, url.unwrap().as_ptr()) })?;
        ready_agent(&client, false, ar)?;
        client.configure()?;
        Ok(client)
    }
}

impl Agent for Client {
    fn fd(&self) -> *mut ssl::PRFileDesc {
        self.fd
    }

    fn handshake(
        &mut self,
        now: &std::time::SystemTime,
        input: &[u8],
        output: &mut [u8],
    ) -> Res<(HandshakeState, usize)> {
        let res = handshake(
            self.fd,
            self.io.borrow_mut(),
            &mut self.auth_required,
            now,
            input,
            output,
        );
        self.st = match &res {
            &Ok((ref state, _)) => state.clone(),
            &Err(ref err) => HandshakeState::Failed(err.clone()),
        };
        res
    }

    fn state(&self) -> &HandshakeState {
        &self.st
    }
}

pub struct Server {
    fd: *mut ssl::PRFileDesc,
    io: Box<AgentIo>,
    st: HandshakeState,
    auth_required: Box<bool>,
}

impl Server {
    pub fn new<T>(certificates: T) -> Res<Self>
    where
        T: IntoIterator,
        T::Item: ToString,
    {
        let io = Box::into_raw(Box::new(AgentIo::new()));
        let ar = Box::into_raw(Box::new(false));
        let server = Server {
            fd: create_fd(io)?,
            io: unsafe { Box::from_raw(io) }, // take ownership
            st: HandshakeState::New,
            auth_required: unsafe { Box::from_raw(ar) }, // take ownership
        };

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
                ssl::SSL_ConfigServerCert(server.fd, *cert.deref(), *key.deref(), null(), 0)
            })?;
        }
        ready_agent(&server, true, ar)?;
        server.configure()?;
        Ok(server)
    }
}

impl Agent for Server {
    fn fd(&self) -> *mut ssl::PRFileDesc {
        self.fd
    }

    fn handshake(
        &mut self,
        now: &std::time::SystemTime,
        input: &[u8],
        output: &mut [u8],
    ) -> Res<(HandshakeState, usize)> {
        let res = handshake(
            self.fd,
            self.io.borrow_mut(),
            &mut self.auth_required,
            now,
            input,
            output,
        );
        self.st = match res {
            Ok((ref state, _)) => state.clone(),
            Err(ref err) => HandshakeState::Failed(err.clone()),
        };
        res
    }

    fn state(&self) -> &HandshakeState {
        &self.st
    }
}
