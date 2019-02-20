use crate::err::{Error, NSPRErrorCodes, PR_SetError, Res};
use crate::prio;
use crate::result;
use crate::ssl;

use std::cmp::min;
use std::collections::linked_list::{Iter, LinkedList};
use std::mem;
use std::os::raw::{c_uint, c_void};
use std::ptr::{null, null_mut};

// Alias common types.
type PrFd = *mut prio::PRFileDesc;
type PrStatus = prio::PRStatus::Type;
const PR_SUCCESS: PrStatus = prio::PRStatus::PR_SUCCESS;
const PR_FAILURE: PrStatus = prio::PRStatus::PR_FAILURE;

// This holds the length of the slice, not the slice itself.
#[derive(Default, Debug)]
struct SslRecordLength {
    epoch: u16,
    ct: ssl::SSLContentType::Type,
    len: usize,
}

/// A slice of the output.
#[derive(Default, Debug)]
pub struct SslRecord<'a> {
    epoch: u16,
    ct: ssl::SSLContentType::Type,
    data: &'a [u8],
}

impl<'a> SslRecord<'a> {
    // Shoves this record into the socket, returns true if blocked.
    fn write(&self, fd: *mut ssl::PRFileDesc) -> Res<()> {
        println!(
            "write record {:?} {:?} {:?}",
            self.epoch,
            self.ct,
            self.data.len()
        );
        let rv = unsafe {
            ssl::SSL_RecordLayerData(
                fd,
                self.epoch,
                self.ct,
                self.data.as_ptr(),
                self.data.len() as c_uint,
            )
        };
        // It's alright if this blocks.
        // That happens if we are waiting on authentication.
        // No need to propagate that because we use the callback.
        let _ = result::result_or_blocked(rv)?;
        Ok(())
    }
}

/// An iterator over the items in SslRecordList.
pub struct SslRecordListIter<'a> {
    output: &'a SslRecordList<'a>,
    iter: Iter<'a, SslRecordLength>,
    offset: usize,
}

impl<'a> Iterator for SslRecordListIter<'a> {
    type Item = SslRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(item) => {
                let start = self.offset;
                self.offset = start + item.len;
                assert!(self.offset <= self.output.buf.len());
                Some(SslRecord {
                    epoch: item.epoch,
                    ct: item.ct,
                    data: &self.output.buf[start..self.offset],
                })
            }
            None => None,
        }
    }
}

#[derive(Default)]
pub struct SslRecordList<'a> {
    buf: &'a mut [u8],
    sizes: LinkedList<SslRecordLength>,
    used: usize,
}

impl<'a> SslRecordList<'a> {
    pub fn new(b: &'a mut [u8]) -> SslRecordList<'a> {
        SslRecordList {
            buf: b,
            sizes: Default::default(),
            used: 0usize,
        }
    }

    fn ingest(&mut self, epoch: u16, ct: ssl::SSLContentType::Type, data: &[u8]) -> Res<()> {
        let end = self.used + data.len();
        assert!(end <= self.buf.len());
        self.buf[self.used..end].copy_from_slice(data);
        // Check if the last thing matches epoch and content type.
        // This assumes that NSS won't be sending multiple different
        // content types for the same epoch, such that we would have
        // to coalesce differently.  By current reckoning, the only
        // way in which different content types might be produced is
        // if an alert is sent after some data.  That would be a
        // terminal condition, so don't stress.
        let add = match self.sizes.back() {
            Some(SslRecordLength {
                epoch: e, ct: c, ..
            }) => {
                assert!(*e <= epoch);
                *e != epoch || *c != ct
            }
            _ => true,
        };
        if add {
            self.sizes.push_back(SslRecordLength {
                epoch,
                ct,
                len: data.len(),
            });
        } else {
            self.sizes.back_mut().unwrap().len += data.len();
        }
        self.used = end;
        Ok(())
    }

    pub fn iter(&'a self) -> SslRecordListIter<'a> {
        SslRecordListIter {
            output: self,
            iter: self.sizes.iter(),
            offset: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    fn available(&self) -> usize {
        self.buf.len() - self.used
    }
}

pub unsafe extern "C" fn ingest_record(
    _fd: *mut ssl::PRFileDesc,
    epoch: ssl::PRUint16,
    ct: ssl::SSLContentType::Type,
    data: *const ssl::PRUint8,
    len: c_uint,
    arg: *mut c_void,
) -> ssl::SECStatus {
    let a = arg as *mut SslRecordList;
    let records = a.as_mut().unwrap();

    let slice = std::slice::from_raw_parts(data, len as usize);
    match records.ingest(epoch, ct, slice) {
        Ok(()) => ssl::SECSuccess,
        _ => ssl::SECFailure,
    }
}

pub fn emit_records(fd: *mut ssl::PRFileDesc, records: SslRecordList) -> Res<()> {
    for i in records.iter() {
        i.write(fd)?;
    }
    Ok(())
}

pub struct AgentIoContext<'a> {
    io: &'a mut AgentIo,
}

impl<'a> Drop for AgentIoContext<'a> {
    fn drop(&mut self) {
        self.io.reset();
    }
}

#[derive(Debug)]
pub struct AgentIo {
    // input is data that is read by TLS.
    input: *const u8,
    // input_available is how much data is left for reading.
    input_available: usize,
    // output contains data that is written by TLS.
    // This uses a static lifetime, because we don't care and
    // are using unsafe to access this anyway.  We police lifetime
    // rules on this manually.
    output: *mut SslRecordList<'static>,
}

impl AgentIo {
    pub fn new() -> AgentIo {
        AgentIo {
            input: null(),
            input_available: 0,
            output: null_mut(),
        }
    }

    unsafe fn borrow<'a>(fd: &'a PrFd) -> &'a mut AgentIo {
        let io = (**fd).secret as *mut AgentIo;
        io.as_mut().unwrap()
    }

    pub fn wrap<'a: 'c, 'b: 'c, 'c>(
        &'a mut self,
        input: &'b [u8],
        output: &'b mut [u8],
    ) -> (AgentIoContext<'c>, Box<SslRecordList<'b>>) {
        assert!(self.input.is_null());
        assert!(self.output.is_null());
        self.input = input.as_ptr();
        self.input_available = input.len();
        let mut out = Box::new(SslRecordList::new(output));
        // Lifetime hack because we need to assign this pointer to AgentIo
        // and AgentIo lives longer than out.  We guarantee that this pointer
        // is set to null before the memory goes out of scope using AgentIoContext.
        self.output = unsafe { mem::transmute(&mut *out) };
        (AgentIoContext { io: self }, out)
    }

    fn reset(&mut self) {
        self.input = null();
        self.input_available = 0;
        self.output = null_mut();
    }

    // Signal that we're blocked.
    fn blocked(amount: usize) -> Res<()> {
        if amount == 0 {
            unsafe { PR_SetError(NSPRErrorCodes::PR_WOULD_BLOCK_ERROR, 0) };
            Err(Error::NoDataAvailable)
        } else {
            Ok(())
        }
    }

    // Take the data provided as input and provide it to the TLS stack.
    fn read_input(&mut self, buf: *mut u8, count: usize) -> Res<usize> {
        let amount = min(self.input_available, count);
        AgentIo::blocked(amount)?;
        let src = unsafe { std::slice::from_raw_parts(self.input, amount) };
        let dst = unsafe { std::slice::from_raw_parts_mut(buf, amount) };
        dst.copy_from_slice(&src);
        self.input = self.input.wrapping_offset(amount as isize);
        self.input_available -= amount;
        Ok(amount)
    }

    // Stage output from TLS into the output buffer.
    fn write_output(&mut self, buf: *const u8, count: usize) -> Res<usize> {
        let out = unsafe { self.output.as_mut().unwrap() };
        let amount = min(out.available(), count);
        AgentIo::blocked(amount)?;
        out.ingest(0, 0, unsafe { std::slice::from_raw_parts(buf, amount) })?;
        Ok(amount)
    }
}

unsafe extern "C" fn agent_close(fd: PrFd) -> PrStatus {
    if let Some(dtor) = (*fd).dtor {
        dtor(fd);
    }
    (*fd).secret = null_mut();
    PR_SUCCESS
}

unsafe extern "C" fn agent_read(fd: PrFd, buf: *mut c_void, amount: prio::PRInt32) -> PrStatus {
    let agent = AgentIo::borrow(&fd);
    if amount <= 0 {
        return PR_FAILURE;
    }
    match agent.read_input(buf as *mut u8, amount as usize) {
        Ok(_) => PR_SUCCESS,
        Err(_) => PR_FAILURE,
    }
}

unsafe extern "C" fn agent_recv(
    fd: PrFd,
    buf: *mut c_void,
    amount: prio::PRInt32,
    flags: prio::PRIntn,
    _timeout: prio::PRIntervalTime,
) -> prio::PRInt32 {
    let agent = AgentIo::borrow(&fd);
    if amount <= 0 || flags != 0 {
        return PR_FAILURE;
    }
    match agent.read_input(buf as *mut u8, amount as usize) {
        Ok(v) => v as prio::PRInt32,
        Err(_) => -1,
    }
}

unsafe extern "C" fn agent_write(fd: PrFd, buf: *const c_void, amount: prio::PRInt32) -> PrStatus {
    let agent = AgentIo::borrow(&fd);
    if amount <= 0 {
        return PR_FAILURE;
    }
    match agent.write_output(buf as *const u8, amount as usize) {
        Ok(amount) => amount as prio::PRInt32,
        Err(_) => -1,
    }
}

unsafe extern "C" fn agent_send(
    fd: PrFd,
    buf: *const c_void,
    amount: prio::PRInt32,
    flags: prio::PRIntn,
    _timeout: prio::PRIntervalTime,
) -> prio::PRInt32 {
    let agent = AgentIo::borrow(&fd);
    println!("send fd {:p} agent {:p} amount {:?}", fd, &agent, amount);

    if amount <= 0 || flags != 0 {
        return PR_FAILURE;
    }
    match agent.write_output(buf as *const u8, amount as usize) {
        Ok(amount) => amount as prio::PRInt32,
        Err(_) => -1,
    }
}

unsafe extern "C" fn agent_available(fd: PrFd) -> prio::PRInt32 {
    let agent = AgentIo::borrow(&fd);
    agent.input_available as prio::PRInt32
}

unsafe extern "C" fn agent_available64(fd: PrFd) -> prio::PRInt64 {
    let agent = AgentIo::borrow(&fd);
    agent.input_available as prio::PRInt64
}

unsafe extern "C" fn agent_fsync(_fd: PrFd) -> PrStatus {
    unimplemented!()
}

unsafe extern "C" fn agent_seek(
    _fd: PrFd,
    _offset: prio::PROffset32,
    _how: prio::PRSeekWhence::Type,
) -> prio::PROffset32 {
    unimplemented!()
}

unsafe extern "C" fn agent_seek64(
    _fd: PrFd,
    _offset: prio::PROffset64,
    _how: prio::PRSeekWhence::Type,
) -> prio::PROffset64 {
    unimplemented!()
}

unsafe extern "C" fn agent_getname(_fd: PrFd, addr: *mut prio::PRNetAddr) -> PrStatus {
    let a = addr.as_mut().unwrap();
    a.inet.family = prio::PR_AF_INET as prio::PRUint16;
    a.inet.port = 0;
    a.inet.ip = 0;
    PR_SUCCESS
}

unsafe extern "C" fn agent_getsockopt(_fd: PrFd, opt: *mut prio::PRSocketOptionData) -> PrStatus {
    let o = opt.as_mut().unwrap();
    if o.option == prio::PRSockOption::PR_SockOpt_Nonblocking {
        o.value.non_blocking = 1;
        return PR_SUCCESS;
    }
    PR_FAILURE
}

pub const METHODS: &'static prio::PRIOMethods = &prio::PRIOMethods {
    file_type: prio::PRDescType::PR_DESC_LAYERED,
    close: Some(agent_close),
    read: Some(agent_read),
    write: Some(agent_write),
    available: Some(agent_available),
    available64: Some(agent_available64),
    fsync: Some(agent_fsync),
    seek: Some(agent_seek),
    seek64: Some(agent_seek64),
    fileInfo: None,
    fileInfo64: None,
    writev: None,
    connect: None,
    accept: None,
    bind: None,
    listen: None,
    shutdown: None,
    recv: Some(agent_recv),
    send: Some(agent_send),
    recvfrom: None,
    sendto: None,
    poll: None,
    acceptread: None,
    transmitfile: None,
    getsockname: Some(agent_getname),
    getpeername: Some(agent_getname),
    reserved_fn_6: None,
    reserved_fn_5: None,
    getsocketoption: Some(agent_getsockopt),
    setsocketoption: None,
    sendfile: None,
    connectcontinue: None,
    reserved_fn_3: None,
    reserved_fn_2: None,
    reserved_fn_1: None,
    reserved_fn_0: None,
};
