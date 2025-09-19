// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![expect(
    clippy::unwrap_used,
    reason = "Let's assume the use of `unwrap` was checked when the use of `unsafe` was reviewed."
)]

use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    fmt::{self, Debug, Display, Formatter},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    os::raw::{c_uint, c_void},
    pin::Pin,
    ptr::{null, null_mut, NonNull},
    rc::Rc,
    slice,
    time::Instant,
};

use neqo_common::{hex_snip_middle, hex_with_len, qdebug, qtrace, qwarn};

pub use crate::{
    agentio::{as_c_void, Record, RecordList},
    cert::CertificateInfo,
};
use crate::{
    agentio::{AgentIo, METHODS},
    assert_initialized,
    auth::AuthenticationStatus,
    constants::{
        Alert, Cipher, Epoch, Extension, Group, SignatureScheme, Version, TLS_VERSION_1_3,
    },
    ech,
    err::{is_blocked, secstatus_to_res, Error, PRErrorCode, Res},
    ext::{ExtensionHandler, ExtensionTracker, SSL_CallExtensionWriterOnEchInner},
    null_safe_slice,
    p11::{self, PrivateKey, PublicKey},
    prio,
    replay::AntiReplay,
    secrets::SecretHolder,
    ssl::{self, PRBool},
    time::{Time, TimeHolder},
};

/// Private trait for Certificate Compression implementation
/// Use `SafeCertCompression` to implement an encoder/decoder instead.
trait UnsafeCertCompression {
    extern "C" fn decode_callback(
        input: *const ssl::SECItem,
        output: *mut ::std::os::raw::c_uchar,
        output_len: usize,
        used_len: *mut usize,
    ) -> ssl::SECStatus;

    extern "C" fn encode_callback(
        input: *const ssl::SECItem,
        output: *mut ssl::SECItem,
    ) -> ssl::SECStatus;
}

/// The trait is used to represent a certificate compression data structure
/// Used in order to enable Certificate Compression extension during TLS connection
pub trait CertificateCompressor {
    /// Certificate Compression identifier as in RFC8879
    const ID: u16;
    /// Certification Compression name (used only for logging/debugging)
    const NAME: &CStr;
    /// Certificate Compression could be used to encode and decode a certificate
    /// though the encoding is not frequently used
    /// Enable decoding field is used to signal to the implementation
    /// to use the encoding as well
    const ENABLE_ENCODING: bool = false;

    /// Certificate Compression encoding function
    ///
    /// This default implementation effectively does nothing.
    /// However, this is only run if `ENABLE_ENCODING` is `true`.
    /// Implementations that set `ENABLE_ENCODING` to `true` need to implement this function.
    ///
    /// # Errors
    /// Encoding was unsuccessful, for example, not enough memory
    fn encode(input: &[u8], output: &mut [u8]) -> Res<usize> {
        let len = std::cmp::min(input.len(), output.len());
        output[..len].copy_from_slice(&input[..len]);
        Ok(len)
    }

    /// Certificate Compression decoding function.
    /// # Errors
    /// Decoding was unsuccessful.
    /// We require a decoder internally to check the length of the decoded buffer.
    /// If the decoded length is not equal to the length of the provided slice
    /// the decoder should return an error.
    fn decode(input: &[u8], output: &mut [u8]) -> Res<()>;
}

/// The trait is responsible for calling `CertificateCompression` encoding and decoding
/// functions using the NSS types
impl<T: CertificateCompressor> UnsafeCertCompression for T {
    extern "C" fn decode_callback(
        input: *const ssl::SECItem,
        output: *mut ::std::os::raw::c_uchar,
        output_len: usize,
        used_len: *mut usize,
    ) -> ssl::SECStatus {
        let Some(input) = NonNull::new(input.cast_mut()) else {
            return ssl::SECFailure;
        };
        if unsafe { input.as_ref().data.is_null() || input.as_ref().len == 0 } {
            return ssl::SECFailure;
        }

        let input_slice = unsafe { null_safe_slice(input.as_ref().data, input.as_ref().len) };
        let output_slice = unsafe { slice::from_raw_parts_mut(output, output_len) };

        if T::decode(input_slice, output_slice).is_err() {
            return ssl::SECFailure;
        }

        unsafe {
            *used_len = output_len;
        }
        ssl::SECSuccess
    }

    extern "C" fn encode_callback(
        input: *const ssl::SECItem,
        output: *mut ssl::SECItem,
    ) -> ssl::SECStatus {
        let Some(input) = NonNull::new(input.cast_mut()) else {
            return ssl::SECFailure;
        };

        let (input_data, input_len) = unsafe {
            let input_ref = input.as_ref();
            (input_ref.data, input_ref.len)
        };

        if input_data.is_null() || input_len == 0 {
            return ssl::SECFailure;
        }
        let input_slice = unsafe { null_safe_slice(input_data, input_len) };

        unsafe {
            p11::SECITEM_AllocItem(
                null_mut(),
                // p11::SECItem is the same as ssl::SECItem
                output.cast::<p11::SECItemStr>(),
                // Compression shouldn't make the thing *longer*,
                // but allocate one extra byte anyway to enable simple testing modes.
                input_len + 1,
            );
        }

        if unsafe { (*output).data.is_null() } {
            return ssl::SECFailure;
        }

        let Ok(output_len) = (unsafe { (*output).len.try_into() }) else {
            return ssl::SECFailure;
        };

        let output_slice = unsafe { slice::from_raw_parts_mut((*output).data, output_len) };

        let Ok(encoded_len) = T::encode(input_slice, output_slice) else {
            return ssl::SECFailure;
        };

        if encoded_len == 0 || encoded_len > output_len {
            return ssl::SECFailure;
        }

        let Ok(encoded_len) = encoded_len.try_into() else {
            return ssl::SECFailure;
        };

        unsafe {
            (*output).len = encoded_len;
        }
        ssl::SECSuccess
    }
}

/// The maximum number of tickets to remember for a given connection.
const MAX_TICKETS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    New,
    InProgress,
    AuthenticationPending,
    /// When encrypted client hello is enabled, the server might engage a fallback.
    /// This is the status that is returned.  The included value is the public
    /// name of the server, which should be used to validate the certificate.
    EchFallbackAuthenticationPending(String),
    Authenticated(PRErrorCode),
    Complete(SecretAgentInfo),
    Failed(Error),
}

impl HandshakeState {
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Complete(_))
    }

    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Complete(_) | Self::Failed(_))
    }

    #[must_use]
    pub const fn authentication_needed(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationPending | Self::EchFallbackAuthenticationPending(_)
        )
    }
}

fn get_alpn(fd: *mut ssl::PRFileDesc, pre: bool) -> Res<Option<String>> {
    let mut alpn_state = ssl::SSLNextProtoState::SSL_NEXT_PROTO_NO_SUPPORT;
    let mut chosen = vec![0_u8; 255];
    let mut chosen_len: c_uint = 0;
    secstatus_to_res(unsafe {
        ssl::SSL_GetNextProto(
            fd,
            &mut alpn_state,
            chosen.as_mut_ptr(),
            &mut chosen_len,
            c_uint::try_from(chosen.len())?,
        )
    })?;

    let alpn = match (pre, alpn_state) {
        (true, ssl::SSLNextProtoState::SSL_NEXT_PROTO_EARLY_VALUE)
        | (
            false,
            ssl::SSLNextProtoState::SSL_NEXT_PROTO_NEGOTIATED
            | ssl::SSLNextProtoState::SSL_NEXT_PROTO_SELECTED,
        ) => {
            chosen.truncate(usize::try_from(chosen_len)?);
            Some(match String::from_utf8(chosen) {
                Ok(a) => a,
                Err(_) => return Err(Error::Internal),
            })
        }
        _ => None,
    };
    qtrace!("[{fd:p}] got ALPN {alpn:?}");
    Ok(alpn)
}

pub struct SecretAgentPreInfo {
    info: ssl::SSLPreliminaryChannelInfo,
    alpn: Option<String>,
}

macro_rules! preinfo_arg {
    ($v:ident, $m:ident, $f:ident: $t:ty $(,)?) => {
        #[must_use]
        pub fn $v(&self) -> Option<$t> {
            match self.info.valuesSet & ssl::$m {
                0 => None,
                _ => Some(
                    <$t>::try_from(self.info.$f)
                        .inspect_err(|e| qdebug!("Invalid value in preinfo: {e:?}"))
                        .ok()?,
                ),
            }
        }
    };
}

impl SecretAgentPreInfo {
    fn new(fd: *mut ssl::PRFileDesc) -> Res<Self> {
        let mut info: MaybeUninit<ssl::SSLPreliminaryChannelInfo> = MaybeUninit::uninit();
        secstatus_to_res(unsafe {
            ssl::SSL_GetPreliminaryChannelInfo(
                fd,
                info.as_mut_ptr(),
                c_uint::try_from(size_of::<ssl::SSLPreliminaryChannelInfo>())?,
            )
        })?;

        Ok(Self {
            info: unsafe { info.assume_init() },
            alpn: get_alpn(fd, true)?,
        })
    }

    preinfo_arg!(version, ssl_preinfo_version, protocolVersion: Version);
    preinfo_arg!(cipher_suite, ssl_preinfo_cipher_suite, cipherSuite: Cipher);
    preinfo_arg!(
        early_data_cipher,
        ssl_preinfo_0rtt_cipher_suite,
        zeroRttCipherSuite: Cipher,
    );

    #[must_use]
    pub const fn early_data(&self) -> bool {
        self.info.canSendEarlyData != 0
    }

    /// # Errors
    ///
    /// If `usize` is less than 32 bits and the value is too large.
    pub fn max_early_data(&self) -> Res<usize> {
        Ok(usize::try_from(self.info.maxEarlyDataSize)?)
    }

    /// Was ECH accepted.
    #[must_use]
    pub const fn ech_accepted(&self) -> Option<bool> {
        if self.info.valuesSet & ssl::ssl_preinfo_ech == 0 {
            None
        } else {
            Some(self.info.echAccepted != 0)
        }
    }

    /// Get the ECH public name that was used.  This will only be available
    /// (that is, not `None`) if `ech_accepted()` returns `false`.
    /// In this case, certificate validation needs to use this name rather
    /// than the original name to validate the certificate.  If
    /// that validation passes (that is, `SecretAgent::authenticated` is called
    /// with `AuthenticationStatus::Ok`), then the handshake will still fail.
    /// After the failed handshake, the state will be `Error::EchRetry`,
    /// which contains a valid ECH configuration.
    ///
    /// # Errors
    ///
    /// When the public name is not valid UTF-8.  (Note: names should be ASCII.)
    pub fn ech_public_name(&self) -> Res<Option<&str>> {
        if self.info.valuesSet & ssl::ssl_preinfo_ech == 0 || self.info.echPublicName.is_null() {
            Ok(None)
        } else {
            let n = unsafe { CStr::from_ptr(self.info.echPublicName) };
            Ok(Some(n.to_str()?))
        }
    }

    #[must_use]
    pub const fn alpn(&self) -> Option<&String> {
        self.alpn.as_ref()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretAgentInfo {
    version: Version,
    cipher: Cipher,
    group: Group,
    resumed: bool,
    early_data: bool,
    ech_accepted: bool,
    alpn: Option<String>,
    signature_scheme: SignatureScheme,
}

impl SecretAgentInfo {
    fn new(fd: *mut ssl::PRFileDesc) -> Res<Self> {
        let mut info: MaybeUninit<ssl::SSLChannelInfo> = MaybeUninit::uninit();
        secstatus_to_res(unsafe {
            ssl::SSL_GetChannelInfo(
                fd,
                info.as_mut_ptr(),
                c_uint::try_from(size_of::<ssl::SSLChannelInfo>())?,
            )
        })?;
        let info = unsafe { info.assume_init() };
        Ok(Self {
            version: info.protocolVersion,
            cipher: info.cipherSuite,
            group: Group::try_from(info.keaGroup)?,
            resumed: info.resumed != 0,
            early_data: info.earlyDataAccepted != 0,
            ech_accepted: info.echAccepted != 0,
            alpn: get_alpn(fd, false)?,
            signature_scheme: SignatureScheme::try_from(info.signatureScheme)?,
        })
    }
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }
    #[must_use]
    pub const fn cipher_suite(&self) -> Cipher {
        self.cipher
    }
    #[must_use]
    pub const fn key_exchange(&self) -> Group {
        self.group
    }
    #[must_use]
    pub const fn resumed(&self) -> bool {
        self.resumed
    }
    #[must_use]
    pub const fn early_data_accepted(&self) -> bool {
        self.early_data
    }
    #[must_use]
    pub const fn ech_accepted(&self) -> bool {
        self.ech_accepted
    }
    #[must_use]
    pub const fn alpn(&self) -> Option<&String> {
        self.alpn.as_ref()
    }
    // TODO: Not used in neqo, but Gecko calls it. Needs a test to call it.
    #[must_use]
    pub const fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

/// `SecretAgent` holds the common parts of client and server.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "This is OK.")]
pub struct SecretAgent {
    fd: *mut ssl::PRFileDesc,
    secrets: SecretHolder,
    raw: Option<bool>,
    io: Pin<Box<AgentIo>>,
    state: HandshakeState,

    /// Records whether authentication of certificates is required.
    auth_required: Pin<Box<bool>>,
    /// Records any fatal alert that is sent by the stack.
    alert: Pin<Box<Option<Alert>>>,
    /// The current time.
    now: TimeHolder,

    extension_handlers: Vec<ExtensionTracker>,

    /// The encrypted client hello (ECH) configuration that is in use.
    /// Empty if ECH is not enabled.
    ech_config: Vec<u8>,
}

impl SecretAgent {
    fn new() -> Res<Self> {
        let mut io = Box::pin(AgentIo::new());
        let fd = Self::create_fd(&mut io)?;
        Ok(Self {
            fd,
            secrets: SecretHolder::default(),
            raw: None,
            io,
            state: HandshakeState::New,

            auth_required: Box::pin(false),
            alert: Box::pin(None),
            now: TimeHolder::default(),

            extension_handlers: Vec::new(),

            ech_config: Vec::new(),
        })
    }

    // Create a new SSL file descriptor.
    //
    // Note that we create separate bindings for PRFileDesc as both
    // ssl::PRFileDesc and prio::PRFileDesc.  This keeps the bindings
    // minimal, but it means that the two forms need casts to translate
    // between them.  ssl::PRFileDesc is left as an opaque type, as the
    // ssl::SSL_* APIs only need an opaque type.
    fn create_fd(io: &mut Pin<Box<AgentIo>>) -> Res<*mut ssl::PRFileDesc> {
        assert_initialized();
        let label = CString::new("sslwrapper")?;
        let id = unsafe { prio::PR_GetUniqueIdentity(label.as_ptr()) };

        let base_fd = unsafe { prio::PR_CreateIOLayerStub(id, METHODS) };
        if base_fd.is_null() {
            return Err(Error::CreateSslSocket);
        }
        let fd = unsafe {
            (*base_fd).secret = as_c_void(io).cast();
            ssl::SSL_ImportFD(null_mut(), base_fd.cast())
        };
        if fd.is_null() {
            unsafe {
                prio::PR_Close(base_fd);
            }
            return Err(Error::CreateSslSocket);
        }
        Ok(fd)
    }

    unsafe extern "C" fn auth_complete_hook(
        arg: *mut c_void,
        _fd: *mut ssl::PRFileDesc,
        _check_sig: PRBool,
        _is_server: PRBool,
    ) -> ssl::SECStatus {
        let auth_required_ptr = arg.cast::<bool>();
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
            let st = arg.cast::<Option<Alert>>().as_mut().unwrap();
            if st.is_none() {
                *st = Some(alert.description);
            } else {
                qwarn!("[{fd:p}] duplicate alert {}", alert.description);
            }
        }
    }

    // Ready this for connecting.
    fn ready(&mut self, is_server: bool, grease: bool) -> Res<()> {
        secstatus_to_res(unsafe {
            ssl::SSL_AuthCertificateHook(
                self.fd,
                Some(Self::auth_complete_hook),
                as_c_void(&mut self.auth_required),
            )
        })?;

        secstatus_to_res(unsafe {
            ssl::SSL_AlertSentCallback(
                self.fd,
                Some(Self::alert_sent_cb),
                as_c_void(&mut self.alert),
            )
        })?;

        self.now.bind(self.fd)?;
        self.configure(grease)?;
        secstatus_to_res(unsafe { ssl::SSL_ResetHandshake(self.fd, PRBool::from(is_server)) })
    }

    /// Default configuration.
    ///
    /// # Errors
    ///
    /// If `set_version_range` fails.
    fn configure(&mut self, grease: bool) -> Res<()> {
        self.set_version_range(TLS_VERSION_1_3, TLS_VERSION_1_3)?;
        self.set_option(ssl::Opt::Locking, false)?;
        self.set_option(ssl::Opt::Tickets, false)?;
        self.set_option(ssl::Opt::OcspStapling, true)?;
        self.set_option(
            ssl::Opt::Grease,
            cfg!(not(feature = "disable-random")) && grease,
        )?;
        self.set_option(
            ssl::Opt::EnableChExtensionPermutation,
            cfg!(not(feature = "disable-random")),
        )?;
        Ok(())
    }

    /// Set the versions that are supported.
    ///
    /// # Errors
    ///
    /// If the range of versions isn't supported.
    pub fn set_version_range(&mut self, min: Version, max: Version) -> Res<()> {
        let range = ssl::SSLVersionRange { min, max };
        secstatus_to_res(unsafe { ssl::SSL_VersionRangeSet(self.fd, &range) })
    }

    /// Enable a set of ciphers.  Note that the order of these is not respected.
    ///
    /// # Errors
    ///
    /// If NSS can't enable or disable ciphers.
    pub fn set_ciphers(&mut self, ciphers: &[Cipher]) -> Res<()> {
        if self.state != HandshakeState::New {
            qwarn!("[{self}] Cannot enable ciphers in state {:?}", self.state);
            return Err(Error::Internal);
        }

        let all_ciphers = unsafe { ssl::SSL_GetImplementedCiphers() };
        let cipher_count = usize::from(unsafe { ssl::SSL_GetNumImplementedCiphers() });
        for i in 0..cipher_count {
            let p = all_ciphers.wrapping_add(i);
            secstatus_to_res(unsafe {
                ssl::SSL_CipherPrefSet(self.fd, i32::from(*p), PRBool::from(false))
            })?;
        }

        for c in ciphers {
            secstatus_to_res(unsafe {
                ssl::SSL_CipherPrefSet(self.fd, i32::from(*c), PRBool::from(true))
            })?;
        }
        Ok(())
    }

    /// Set key exchange groups.
    ///
    /// # Errors
    ///
    /// If the underlying API fails (which shouldn't happen).
    pub fn set_groups(&mut self, groups: &[Group]) -> Res<()> {
        // SSLNamedGroup is a different size to Group, so copy one by one.
        let group_vec: Vec<_> = groups
            .iter()
            .map(|&g| ssl::SSLNamedGroup::Type::from(g))
            .collect();

        let ptr = group_vec.as_slice().as_ptr();
        secstatus_to_res(unsafe {
            ssl::SSL_NamedGroupConfig(self.fd, ptr, c_uint::try_from(group_vec.len())?)
        })
    }

    /// Set the number of additional key shares that will be sent in the client hello
    ///
    /// # Errors
    ///
    /// If the underlying API fails (which shouldn't happen).
    pub fn send_additional_key_shares(&mut self, count: usize) -> Res<()> {
        secstatus_to_res(unsafe {
            ssl::SSL_SendAdditionalKeyShares(self.fd, c_uint::try_from(count)?)
        })
    }

    /// Set TLS options.
    ///
    /// # Errors
    ///
    /// Returns an error if the option or option value is invalid; i.e., never.
    pub fn set_option(&self, opt: ssl::Opt, value: bool) -> Res<()> {
        opt.set(self.fd, value)
    }

    /// Enable 0-RTT.
    ///
    /// # Errors
    ///
    /// See `set_option`.
    pub fn enable_0rtt(&self) -> Res<()> {
        self.set_option(ssl::Opt::EarlyData, true)
    }

    /// Disable the `EndOfEarlyData` message.
    ///
    /// # Errors
    ///
    /// See `set_option`.
    pub fn disable_end_of_early_data(&self) -> Res<()> {
        self.set_option(ssl::Opt::SuppressEndOfEarlyData, true)
    }

    /// `set_alpn` sets a list of preferred protocols, starting with the most preferred.
    /// Though ALPN [RFC7301] permits octet sequences, this only allows for UTF-8-encoded
    /// strings.
    ///
    /// This asserts if no items are provided, or if any individual item is longer than
    /// 255 octets in length.
    ///
    /// # Errors
    ///
    /// If the list of protocols is empty, contains an empty value, or
    /// contains a value longer than 255 bytes.
    ///
    /// [RFC7301]: https://datatracker.ietf.org/doc/html/rfc7301
    pub fn set_alpn<A: AsRef<[u8]>>(&mut self, protocols: &[A]) -> Res<()> {
        // Prepare to encode.
        let len = protocols.len() + protocols.iter().map(|p| p.as_ref().len()).sum::<usize>();
        let mut encoded = Vec::with_capacity(len);
        let mut add = |v: &A| -> Res<()> {
            let v = v.as_ref();
            u8::try_from(v.len()).map_or(Err(Error::InvalidAlpn), |s| {
                if s > 0 {
                    encoded.push(s);
                    encoded.extend_from_slice(v);
                    Ok(())
                } else {
                    Err(Error::InvalidAlpn)
                }
            })
        };

        // NSS inherited an idiosyncratic API as a result of having implemented NPN
        // before ALPN.  For that reason, we need to put the "best" option last.
        let (first, rest) = protocols.split_first().ok_or(Error::InvalidAlpn)?;
        for v in rest {
            add(v)?;
        }
        add(first)?;
        debug_assert_eq!(len, encoded.len());

        // Now give the result to NSS.
        secstatus_to_res(unsafe {
            ssl::SSL_SetNextProtoNego(
                self.fd,
                encoded.as_slice().as_ptr(),
                c_uint::try_from(encoded.len())?,
            )
        })
    }

    /// Install a certificate compression mechanism.
    ///
    /// # Errors
    /// If the compression mechanism with the same id is already registered
    /// If too many compression mechanisms are already registered
    ///
    /// This returns an error if the certificate compression could not be established
    ///
    /// [RFC8879]: https://datatracker.ietf.org/doc/rfc8879/
    pub fn set_certificate_compression<T: CertificateCompressor>(&mut self) -> Res<()> {
        if T::ID == 0 {
            return Err(Error::InvalidCertificateCompressionID);
        }

        let compressor: ssl::SSLCertificateCompressionAlgorithm =
            ssl::SSLCertificateCompressionAlgorithm {
                id: T::ID,
                name: T::NAME.as_ptr(),
                encode: T::ENABLE_ENCODING.then_some(<T as UnsafeCertCompression>::encode_callback),
                decode: Some(<T as UnsafeCertCompression>::decode_callback),
            };
        unsafe { ssl::SSL_SetCertificateCompressionAlgorithm(self.fd, compressor) }
    }

    /// Install an extension handler.
    ///
    /// This can be called multiple times with different values for `ext`.  The handler is provided
    /// as `Rc<RefCell<dyn T>>` so that the caller is able to hold a reference to the handler
    /// and later access any state that it accumulates.
    ///
    /// # Errors
    ///
    /// When the extension handler can't be successfully installed.
    pub fn extension_handler(
        &mut self,
        ext: Extension,
        handler: Rc<RefCell<dyn ExtensionHandler>>,
    ) -> Res<()> {
        let tracker = unsafe { ExtensionTracker::new(self.fd, ext, handler)? };
        self.extension_handlers.push(tracker);
        Ok(())
    }

    // This function tracks whether handshake() or handshake_raw() was used
    // and prevents the other from being used.
    fn set_raw(&mut self, r: bool) -> Res<()> {
        if let Some(raw) = self.raw {
            if raw == r {
                Ok(())
            } else {
                Err(Error::MixedHandshakeMethod)
            }
        } else {
            self.secrets.register(self.fd)?;
            self.raw = Some(r);
            Ok(())
        }
    }

    /// Get information about the connection.
    /// This includes the version, ciphersuite, and ALPN.
    ///
    /// Calling this function returns None until the connection is complete.
    #[must_use]
    pub const fn info(&self) -> Option<&SecretAgentInfo> {
        match &self.state {
            HandshakeState::Complete(info) => Some(info),
            _ => None,
        }
    }

    /// Get any preliminary information about the status of the connection.
    ///
    /// This includes whether 0-RTT was accepted and any information related to that.
    /// Calling this function collects all the relevant information.
    ///
    /// # Errors
    ///
    /// When the underlying socket functions fail.
    pub fn preinfo(&self) -> Res<SecretAgentPreInfo> {
        SecretAgentPreInfo::new(self.fd)
    }

    /// Get the peer's certificate chain.
    #[must_use]
    pub fn peer_certificate(&self) -> Option<CertificateInfo> {
        CertificateInfo::new(self.fd)
    }

    /// Return any fatal alert that the TLS stack might have sent.
    #[must_use]
    pub fn alert(&self) -> Option<Alert> {
        *self.alert
    }

    /// Call this function to mark the peer as authenticated.
    ///
    /// # Panics
    ///
    /// If the handshake doesn't need to be authenticated.
    pub fn authenticated(&mut self, status: AuthenticationStatus) {
        assert!(self.state.authentication_needed());
        *self.auth_required = false;
        self.state = HandshakeState::Authenticated(status.into());
    }

    fn capture_error<T>(&mut self, res: Res<T>) -> Res<T> {
        if let Err(e) = res {
            let e = ech::convert_ech_error(self.fd, e);
            qwarn!("[{self}] error: {e:?}");
            self.state = HandshakeState::Failed(e.clone());
            Err(e)
        } else {
            res
        }
    }

    fn update_state(&mut self, res: Res<()>) -> Res<()> {
        self.state = if is_blocked(&res) {
            if *self.auth_required {
                self.preinfo()?.ech_public_name()?.map_or(
                    HandshakeState::AuthenticationPending,
                    |public_name| {
                        HandshakeState::EchFallbackAuthenticationPending(public_name.to_owned())
                    },
                )
            } else {
                HandshakeState::InProgress
            }
        } else {
            self.capture_error(res)?;
            let info = self.capture_error(SecretAgentInfo::new(self.fd))?;
            HandshakeState::Complete(info)
        };
        qdebug!("[{self}] state -> {:?}", self.state);
        Ok(())
    }

    /// Drive the TLS handshake, taking bytes from `input` and putting
    /// any bytes necessary into `output`.
    /// This takes the current time as `now`.
    /// On success a tuple of a `HandshakeState` and usize indicate whether the handshake
    /// is complete and how many bytes were written to `output`, respectively.
    /// If the state is `HandshakeState::AuthenticationPending`, then ONLY call this
    /// function if you want to proceed, because this will mark the certificate as OK.
    ///
    /// # Errors
    ///
    /// When the handshake fails this returns an error.
    pub fn handshake(&mut self, now: Instant, input: &[u8]) -> Res<Vec<u8>> {
        self.now.set(now)?;
        self.set_raw(false)?;

        let rv = {
            // Within this scope, _h maintains a mutable reference to self.io.
            let _h = self.io.wrap(input);
            match self.state {
                HandshakeState::Authenticated(err) => unsafe {
                    ssl::SSL_AuthCertificateComplete(self.fd, err)
                },
                _ => unsafe { ssl::SSL_ForceHandshake(self.fd) },
            }
        };
        // Take before updating state so that we leave the output buffer empty
        // even if there is an error.
        let output = self.io.take_output();
        self.update_state(secstatus_to_res(rv))?;
        Ok(output)
    }

    /// Setup to receive records for raw handshake functions.
    fn setup_raw(&mut self) -> Res<Pin<Box<RecordList>>> {
        self.set_raw(true)?;
        self.capture_error(RecordList::setup(self.fd))
    }

    /// Drive the TLS handshake, but get the raw content of records, not
    /// protected records as bytes. This function is incompatible with
    /// `handshake()`; use either this or `handshake()` exclusively.
    ///
    /// Ideally, this only includes records from the current epoch.
    /// If you send data from multiple epochs, you might end up being sad.
    ///
    /// # Errors
    ///
    /// When the handshake fails this returns an error.
    pub fn handshake_raw(&mut self, now: Instant, input: Option<Record>) -> Res<RecordList> {
        self.now.set(now)?;
        let records = self.setup_raw()?;

        // Fire off any authentication we might need to complete.
        if let HandshakeState::Authenticated(err) = self.state {
            let result =
                secstatus_to_res(unsafe { ssl::SSL_AuthCertificateComplete(self.fd, err) });
            qdebug!("[{self}] SSL_AuthCertificateComplete: {result:?}");
            // This should return SECSuccess, so don't use update_state().
            self.capture_error(result)?;
        }

        // Feed in any records.
        if let Some(rec) = input {
            self.capture_error(rec.write(self.fd))?;
        }

        // Drive the handshake once more.
        let rv = secstatus_to_res(unsafe { ssl::SSL_ForceHandshake(self.fd) });
        self.update_state(rv)?;

        Ok(*Pin::into_inner(records))
    }

    /// # Panics
    ///
    /// If setup fails.
    pub fn close(&mut self) {
        // It should be safe to close multiple times.
        if self.fd.is_null() {
            return;
        }
        #[expect(
            clippy::branches_sharing_code,
            reason = "The PR_Close calls cannot be run after dropping the returned values."
        )]
        if self.raw == Some(true) {
            // Need to hold the record list in scope until the close is done.
            let _records = self.setup_raw().expect("Can only close");
            unsafe {
                prio::PR_Close(self.fd.cast());
            }
        } else {
            // Need to hold the IO wrapper in scope until the close is done.
            let _io = self.io.wrap(&[]);
            unsafe {
                prio::PR_Close(self.fd.cast());
            }
        }
        let _output = self.io.take_output();
        self.fd = null_mut();
    }

    /// State returns the status of the handshake.
    #[must_use]
    pub const fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Check if the indicated secret is ready for installation.
    #[must_use]
    pub fn has_secret(&self, epoch: Epoch) -> bool {
        self.secrets.has(epoch)
    }

    /// Take a read secret.  This will only return a non-`None` value once.
    #[must_use]
    pub fn read_secret(&mut self, epoch: Epoch) -> Option<p11::SymKey> {
        self.secrets.take_read(epoch)
    }

    /// Take a write secret.
    #[must_use]
    pub fn write_secret(&mut self, epoch: Epoch) -> Option<p11::SymKey> {
        self.secrets.take_write(epoch)
    }

    /// Get the active ECH configuration, which is empty if ECH is disabled.
    #[must_use]
    pub fn ech_config(&self) -> &[u8] {
        &self.ech_config
    }
}

impl Drop for SecretAgent {
    fn drop(&mut self) {
        self.close();
    }
}

impl Display for SecretAgent {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Agent {:p}", self.fd)
    }
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct ResumptionToken {
    token: Vec<u8>,
    expiration_time: Instant,
}

impl Debug for ResumptionToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumptionToken")
            .field("token", &hex_snip_middle(&self.token))
            .field("expiration_time", &self.expiration_time)
            .finish()
    }
}

impl AsRef<[u8]> for ResumptionToken {
    fn as_ref(&self) -> &[u8] {
        &self.token
    }
}

impl ResumptionToken {
    #[must_use]
    pub const fn new(token: Vec<u8>, expiration_time: Instant) -> Self {
        Self {
            token,
            expiration_time,
        }
    }

    #[must_use]
    pub const fn expiration_time(&self) -> Instant {
        self.expiration_time
    }
}

/// A TLS Client.
#[derive(Debug)]
pub struct Client {
    agent: SecretAgent,

    /// The name of the server we're attempting a connection to.
    server_name: String,
    /// Records the resumption tokens we've received.
    #[expect(clippy::box_collection, reason = "We need the Box.")]
    resumption: Pin<Box<Vec<ResumptionToken>>>,
}

impl Client {
    /// Create a new client agent.
    ///
    /// # Errors
    ///
    /// Errors returned if the socket can't be created or configured.
    pub fn new<I: Into<String>>(server_name: I, grease: bool) -> Res<Self> {
        let server_name = server_name.into();
        let mut agent = SecretAgent::new()?;
        let url = CString::new(server_name.as_bytes())?;
        secstatus_to_res(unsafe { ssl::SSL_SetURL(agent.fd, url.as_ptr()) })?;
        agent.ready(false, grease)?;
        let mut client = Self {
            agent,
            server_name,
            resumption: Box::pin(Vec::new()),
        };
        client.ready()?;
        Ok(client)
    }

    unsafe extern "C" fn resumption_token_cb(
        fd: *mut ssl::PRFileDesc,
        token: *const u8,
        len: c_uint,
        arg: *mut c_void,
    ) -> ssl::SECStatus {
        let mut info: MaybeUninit<ssl::SSLResumptionTokenInfo> = MaybeUninit::uninit();
        let Ok(info_len) = c_uint::try_from(size_of::<ssl::SSLResumptionTokenInfo>()) else {
            return ssl::SECFailure;
        };
        let info_res = &ssl::SSL_GetResumptionTokenInfo(token, len, info.as_mut_ptr(), info_len);
        if info_res.is_err() {
            // Ignore the token.
            return ssl::SECSuccess;
        }
        let expiration_time = info.assume_init().expirationTime;
        if ssl::SSL_DestroyResumptionTokenInfo(info.as_mut_ptr()).is_err() {
            // Ignore the token.
            return ssl::SECSuccess;
        }
        let Some(resumption) = arg.cast::<Vec<ResumptionToken>>().as_mut() else {
            return ssl::SECFailure;
        };
        let Ok(len) = usize::try_from(len) else {
            return ssl::SECFailure;
        };
        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(null_safe_slice(token, len));
        qdebug!("[{fd:p}] Got resumption token {}", hex_snip_middle(&v));

        if resumption.len() >= MAX_TICKETS {
            resumption.remove(0);
        }
        if let Ok(t) = Time::try_from(expiration_time) {
            resumption.push(ResumptionToken::new(v, *t));
        }
        ssl::SECSuccess
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    fn ready(&mut self) -> Res<()> {
        let fd = self.fd;
        unsafe {
            ssl::SSL_SetResumptionTokenCallback(
                fd,
                Some(Self::resumption_token_cb),
                as_c_void(&mut self.resumption),
            )
        }
    }

    /// Take a resumption token.
    #[must_use]
    pub fn resumption_token(&mut self) -> Option<ResumptionToken> {
        (*self.resumption).pop()
    }

    /// Check if there are more resumption tokens.
    #[must_use]
    pub fn has_resumption_token(&self) -> bool {
        !(*self.resumption).is_empty()
    }

    /// Enable resumption, using a token previously provided.
    ///
    /// # Errors
    ///
    /// Error returned when the resumption token is invalid or
    /// the socket is not able to use the value.
    pub fn enable_resumption<A: AsRef<[u8]>>(&mut self, token: A) -> Res<()> {
        unsafe {
            ssl::SSL_SetResumptionToken(
                self.agent.fd,
                token.as_ref().as_ptr(),
                c_uint::try_from(token.as_ref().len())?,
            )
        }
    }

    /// Enable encrypted client hello (ECH), using the encoded `ECHConfigList`.
    ///
    /// When ECH is enabled, a client needs to look for `Error::EchRetry` as a
    /// failure code.  If `Error::EchRetry` is received when connecting, the
    /// connection attempt should be retried and the included value provided
    /// to this function (instead of what is received from DNS).
    ///
    /// Calling this function with an empty value for `ech_config_list` enables
    /// ECH greasing.  When that is done, there is no need to look for `EchRetry`
    ///
    /// # Errors
    ///
    /// Error returned when the configuration is invalid.
    pub fn enable_ech<A: AsRef<[u8]>>(&mut self, ech_config_list: A) -> Res<()> {
        let config = ech_config_list.as_ref();
        qdebug!("[{self}] Enable ECH for a server: {}", hex_with_len(config));
        self.ech_config = Vec::from(config);
        if config.is_empty() {
            unsafe { ech::SSL_EnableTls13GreaseEch(self.agent.fd, PRBool::from(true)) }
        } else {
            unsafe {
                ech::SSL_SetClientEchConfigs(
                    self.agent.fd,
                    config.as_ptr(),
                    c_uint::try_from(config.len())?,
                )?;
                // If the ECH configuration is valid, and only then,
                // allow writing of different transport parameters to the inner and outer
                // ClientHello. Avoid setting this otherwise, as the transport
                // parameter extension handler filters out essential values from the
                // outer ClientHello. Under normal operation, NSS reports to
                // extension writers that an ordinary, non-ECH ClientHello is an
                // outer ClientHello, resulting in unwanted filtering.
                SSL_CallExtensionWriterOnEchInner(self.fd, PRBool::from(true))
            }
        }
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

impl Display for Client {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Client {:p}", self.agent.fd)
    }
}

/// `ZeroRttCheckResult` encapsulates the options for handling a `ClientHello`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZeroRttCheckResult {
    /// Accept 0-RTT.
    Accept,
    /// Reject 0-RTT, but continue the handshake normally.
    Reject,
    /// Send `HelloRetryRequest` (probably not needed for QUIC).
    HelloRetryRequest(Vec<u8>),
    /// Fail the handshake.
    Fail,
}

/// A `ZeroRttChecker` is used by the agent to validate the application token (as provided by
/// `send_ticket`)
pub trait ZeroRttChecker: Debug + Unpin {
    fn check(&self, token: &[u8]) -> ZeroRttCheckResult;
}

/// Using `AllowZeroRtt` for the implementation of `ZeroRttChecker` means
/// accepting 0-RTT always.  This generally isn't a great idea, so this
/// generates a strong warning when it is used.
#[derive(Debug)]
pub struct AllowZeroRtt {}
impl ZeroRttChecker for AllowZeroRtt {
    fn check(&self, _token: &[u8]) -> ZeroRttCheckResult {
        qwarn!("AllowZeroRtt accepting 0-RTT");
        ZeroRttCheckResult::Accept
    }
}

#[derive(Debug)]
struct ZeroRttCheckState {
    checker: Pin<Box<dyn ZeroRttChecker>>,
}

impl ZeroRttCheckState {
    pub fn new(checker: Box<dyn ZeroRttChecker>) -> Self {
        Self {
            checker: Pin::new(checker),
        }
    }
}

#[derive(Debug)]
pub struct Server {
    agent: SecretAgent,
    /// This holds the HRR callback context.
    zero_rtt_check: Option<Pin<Box<ZeroRttCheckState>>>,
}

impl Server {
    /// Create a new server agent.
    ///
    /// # Errors
    ///
    /// Errors returned when NSS fails.
    pub fn new<A: AsRef<str>>(certificates: &[A]) -> Res<Self> {
        let mut agent = SecretAgent::new()?;

        for n in certificates {
            let c = CString::new(n.as_ref())?;
            let cert_ptr = unsafe { p11::PK11_FindCertFromNickname(c.as_ptr(), null_mut()) };
            let Ok(cert) = p11::Certificate::from_ptr(cert_ptr) else {
                return Err(Error::CertificateLoading);
            };
            let key_ptr = unsafe { p11::PK11_FindKeyByAnyCert(*cert, null_mut()) };
            let Ok(key) = PrivateKey::from_ptr(key_ptr) else {
                return Err(Error::CertificateLoading);
            };
            secstatus_to_res(unsafe {
                ssl::SSL_ConfigServerCert(agent.fd, (*cert).cast(), (*key).cast(), null(), 0)
            })?;
        }

        agent.ready(true, true)?;
        Ok(Self {
            agent,
            zero_rtt_check: None,
        })
    }

    unsafe extern "C" fn hello_retry_cb(
        first_hello: PRBool,
        client_token: *const u8,
        client_token_len: c_uint,
        retry_token: *mut u8,
        retry_token_len: *mut c_uint,
        retry_token_max: c_uint,
        arg: *mut c_void,
    ) -> ssl::SSLHelloRetryRequestAction::Type {
        if first_hello == 0 {
            // On the second ClientHello after HelloRetryRequest, skip checks.
            return ssl::SSLHelloRetryRequestAction::ssl_hello_retry_accept;
        }

        let check_state = arg.cast::<ZeroRttCheckState>().as_mut().unwrap();
        let token = null_safe_slice(client_token, usize::try_from(client_token_len).unwrap());
        match check_state.checker.check(token) {
            ZeroRttCheckResult::Accept => ssl::SSLHelloRetryRequestAction::ssl_hello_retry_accept,
            ZeroRttCheckResult::Fail => ssl::SSLHelloRetryRequestAction::ssl_hello_retry_fail,
            ZeroRttCheckResult::Reject => {
                ssl::SSLHelloRetryRequestAction::ssl_hello_retry_reject_0rtt
            }
            ZeroRttCheckResult::HelloRetryRequest(tok) => {
                // Don't bother propagating errors from this, because it should be caught in
                // testing.
                assert!(tok.len() <= usize::try_from(retry_token_max).unwrap());
                let slc = slice::from_raw_parts_mut(retry_token, tok.len());
                slc.copy_from_slice(&tok);
                *retry_token_len = c_uint::try_from(tok.len()).unwrap();
                ssl::SSLHelloRetryRequestAction::ssl_hello_retry_request
            }
        }
    }

    /// Enable 0-RTT.  This shadows the function of the same name that can be accessed
    /// via the Deref implementation on Server.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying NSS functions fail.
    pub fn enable_0rtt(
        &mut self,
        anti_replay: &AntiReplay,
        max_early_data: u32,
        checker: Box<dyn ZeroRttChecker>,
    ) -> Res<()> {
        let mut check_state = Box::pin(ZeroRttCheckState::new(checker));
        unsafe {
            ssl::SSL_HelloRetryRequestCallback(
                self.agent.fd,
                Some(Self::hello_retry_cb),
                as_c_void(&mut check_state),
            )
        }?;
        unsafe { ssl::SSL_SetMaxEarlyDataSize(self.agent.fd, max_early_data) }?;
        self.zero_rtt_check = Some(check_state);
        self.agent.enable_0rtt()?;
        anti_replay.config_socket(self.fd)?;
        Ok(())
    }

    /// Send a session ticket to the client.
    /// This adds |extra| application-specific content into that ticket.
    /// The records that are sent are captured and returned.
    ///
    /// # Errors
    ///
    /// If NSS is unable to send a ticket, or if this agent is incorrectly configured.
    pub fn send_ticket(&mut self, now: Instant, extra: &[u8]) -> Res<RecordList> {
        self.agent.now.set(now)?;
        let records = self.setup_raw()?;

        unsafe {
            ssl::SSL_SendSessionTicket(self.fd, extra.as_ptr(), c_uint::try_from(extra.len())?)
        }?;

        Ok(*Pin::into_inner(records))
    }

    /// Enable encrypted client hello (ECH).
    ///
    /// # Errors
    ///
    /// Fails when NSS cannot create a key pair.
    pub fn enable_ech(
        &mut self,
        config: u8,
        public_name: &str,
        sk: &PrivateKey,
        pk: &PublicKey,
    ) -> Res<()> {
        let cfg = ech::encode_config(config, public_name, pk)?;
        qdebug!("[{self}] Enable ECH for a server: {}", hex_with_len(&cfg));
        unsafe {
            ech::SSL_SetServerEchConfigs(
                self.agent.fd,
                **pk,
                **sk,
                cfg.as_ptr(),
                c_uint::try_from(cfg.len())?,
            )?;
        };
        self.ech_config = cfg;
        Ok(())
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

impl Display for Server {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Server {:p}", self.agent.fd)
    }
}

/// A generic container for Client or Server.
#[derive(Debug)]
pub enum Agent {
    Client(Client),
    Server(Server),
}

impl Deref for Agent {
    type Target = SecretAgent;
    fn deref(&self) -> &SecretAgent {
        match self {
            Self::Client(c) => c,
            Self::Server(s) => s,
        }
    }
}

impl DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut SecretAgent {
        match self {
            Self::Client(c) => c,
            Self::Server(s) => s,
        }
    }
}

impl From<Client> for Agent {
    fn from(c: Client) -> Self {
        Self::Client(c)
    }
}

impl From<Server> for Agent {
    fn from(s: Server) -> Self {
        Self::Server(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::ResumptionToken;

    #[test]
    fn resumption_token_debug_impl() {
        let now = test_fixture::now();
        let token = [
            2, 0, 6, 60, 37, 21, 238, 165, 182, 0, 6, 60, 77, 81, 157, 101, 182, 0, 6, 60, 37, 21,
            238, 165, 182, 0, 2, 163, 0, 0, 0, 0, 1, 72, 146, 254, 127, 255, 255, 255, 255, 0, 1,
            73, 48, 130, 1, 69, 48, 129, 236, 160, 3, 2, 1, 2, 2, 5, 0, 176, 13, 245, 143, 48, 10,
            6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 15, 49, 13, 48, 11, 6, 3, 85, 4, 3, 19, 4,
            116, 101, 115, 116, 48, 30, 23, 13, 49, 57, 48, 49, 50, 55, 49, 50, 50, 54, 52, 55, 90,
            23, 13, 49, 57, 48, 52, 50, 55, 49, 50, 50, 54, 52, 55, 90, 48, 15, 49, 13, 48, 11, 6,
            3, 85, 4, 3, 19, 4, 116, 101, 115, 116, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2,
            1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 42, 240, 199, 17, 152, 64, 127,
            175, 32, 106, 156, 147, 147, 171, 185, 13, 157, 177, 225, 249, 112, 141, 249, 175, 72,
            224, 44, 119, 74, 249, 38, 109, 45, 217, 239, 119, 190, 34, 246, 151, 97, 85, 39, 175,
            182, 174, 5, 16, 183, 139, 81, 228, 52, 245, 172, 45, 183, 68, 82, 214, 10, 3, 114, 4,
            163, 53, 48, 51, 48, 25, 6, 3, 85, 29, 17, 4, 18, 48, 16, 130, 14, 115, 101, 114, 118,
            101, 114, 46, 101, 120, 97, 109, 112, 108, 101, 48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0,
            48, 11, 6, 3, 85, 29, 15, 4, 4, 3, 2, 7, 128, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3,
            2, 3, 72, 0, 48, 69, 2, 32, 118, 227, 238, 3, 17, 159, 222, 78, 215, 173, 203, 63, 51,
            101, 41, 145, 17, 156, 179, 18, 64, 146, 197, 54, 64, 212, 255, 201, 133, 92, 244, 58,
            2, 33, 0, 148, 138, 31, 164, 15, 1, 107, 82, 152, 245, 77, 127, 251, 227, 229, 183, 33,
            162, 111, 169, 222, 240, 171, 167, 99, 81, 10, 183, 76, 80, 130, 65, 0, 0, 0, 5, 91,
            58, 58, 49, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 3,
            4, 0, 6, 60, 37, 21, 238, 165, 182, 0, 4, 0, 0, 1, 0, 0, 8, 0, 0, 0, 255, 0, 17, 236,
            0, 4, 3, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 19, 1, 1, 48, 245, 92, 231, 183, 9, 67, 178, 200, 227, 203, 91,
            5, 146, 135, 61, 159, 135, 68, 96, 200, 86, 35, 189, 174, 81, 95, 157, 75, 177, 235,
            124, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1,
            50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 2,
            104, 51, 1, 34, 56, 7, 64, 215, 199, 178, 229, 41, 63, 246, 119, 142, 0, 0, 0, 0, 86,
            68, 109, 48, 102, 65, 96, 24, 170, 163, 83, 214, 9, 243, 208, 236, 0, 224, 110, 111,
            243, 244, 243, 4, 172, 188, 247, 135, 255, 109, 241, 240, 77, 178, 162, 32, 255, 45,
            207, 25, 89, 74, 86, 140, 114, 11, 192, 20, 144, 139, 49, 228, 250, 252, 228, 107, 5,
            62, 203, 139, 146, 248, 73, 124, 72, 94, 138, 216, 190, 223, 150, 181, 55, 62, 32, 13,
            231, 230, 104, 142, 27, 182, 15, 13, 116, 26, 234, 154, 228, 241, 134, 131, 25, 214,
            229, 187, 181, 219, 209, 217, 53, 162, 177, 203, 100, 80, 175, 64, 226, 159, 115, 202,
            43, 68, 72, 160, 34, 214, 158, 4, 242, 7, 13, 132, 20, 128, 160, 237, 168, 122, 66, 37,
            54, 11, 116, 148, 94, 173, 80, 228, 7, 89, 223, 156, 249, 22, 50, 62, 33, 22, 157, 115,
            28, 195, 4, 220, 57, 62, 204, 222, 188, 211, 82, 34, 121, 54, 106, 197, 183, 98, 155,
            36, 249, 164, 205, 114, 61, 39, 144, 54, 43, 180, 25, 28, 130, 80, 22, 109, 133, 27,
            87, 184, 66, 54, 117, 151, 113, 36, 172, 98, 31, 60, 42, 85, 190, 148, 160, 65, 222,
            186, 200, 101, 183, 103, 23, 95, 97, 7, 248, 159, 114, 229, 74, 252, 55, 68, 254, 63,
            244, 195, 194, 99, 118, 60, 231, 118, 219, 241, 146, 94, 249, 94, 40, 231, 103, 238,
            215, 120, 60, 213, 142, 121, 11, 15, 251, 195, 120, 39, 17, 117, 183, 1, 90, 178, 149,
            74, 184, 51, 9, 38, 114, 144, 66, 153,
        ];
        let resumption_token = ResumptionToken::new(token.to_vec(), now);
        let expected = format!("ResumptionToken {{ token: \"[848]: 0200063c2515eea5..b833092672904299\", expiration_time: {now:?} }}");
        assert_eq!(format!("{resumption_token:?}"), expected);
    }
}
