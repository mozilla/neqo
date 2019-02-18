use crate::err::{Error, NSPRErrorCodes, PR_SetError, Res};
use crate::prio;

use std::cmp::min;
use std::os::raw::c_void;
use std::ptr::{null, null_mut};

// Alias common types.
type PrFd = *mut prio::PRFileDesc;
type PrStatus = prio::PRStatus::Type;
const PR_SUCCESS: PrStatus = prio::PRStatus::PR_SUCCESS;
const PR_FAILURE: PrStatus = prio::PRStatus::PR_FAILURE;

pub struct AgentIo {
    // input is data that is read by TLS.
    input: *const u8,
    // input_available is how much data is left for reading.
    input_available: usize,
    // output is data that is written by TLS.
    output: *mut u8,
    // output_available is how much space is left for writing.
    output_available: usize,
    // output_written is how much data has already been written.
    output_written: usize,
}

pub struct AgentIoCleanup<'a> {
    io: &'a mut AgentIo,
}

impl<'a> Into<usize> for AgentIoCleanup<'a> {
    fn into(self) -> usize {
        let written = self.io.output_written;
        self.io.reset();
        written
    }
}

impl AgentIo {
    pub fn new() -> AgentIo {
        AgentIo {
            input: null(),
            input_available: 0,
            output: null_mut(),
            output_available: 0,
            output_written: 0,
        }
    }

    unsafe fn borrow<'a>(fd: PrFd) -> &'a mut AgentIo {
        let io = (*fd).secret as *mut AgentIo;
        io.as_mut().unwrap()
    }

    pub fn setup<'a>(&'a mut self, input: &[u8], output: &mut [u8]) -> AgentIoCleanup<'a> {
        self.input = input.as_ptr();
        self.input_available = input.len();
        self.output = output.as_mut_ptr();
        self.output_available = output.len();
        self.output_written = 0;
        AgentIoCleanup { io: self }
    }

    fn reset(&mut self) {
        self.input_available = 0;
        self.output_available = 0;
        self.output_written = 0;
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
        let amount = min(self.output_available, count);
        AgentIo::blocked(amount)?;
        let src = unsafe { std::slice::from_raw_parts(buf, amount) };
        let dst = unsafe { std::slice::from_raw_parts_mut(self.output, amount) };
        dst.copy_from_slice(src);
        self.output = self.output.wrapping_offset(amount as isize);
        self.output_available -= amount;
        self.output_written += amount;
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
    let agent = AgentIo::borrow(fd);
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
    let agent = AgentIo::borrow(fd);
    if amount <= 0 || flags != 0 {
        return PR_FAILURE;
    }
    match agent.read_input(buf as *mut u8, amount as usize) {
        Ok(v) => v as prio::PRInt32,
        Err(_) => -1,
    }
}

unsafe extern "C" fn agent_write(fd: PrFd, buf: *const c_void, amount: prio::PRInt32) -> PrStatus {
    let agent = AgentIo::borrow(fd);
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
    let agent = AgentIo::borrow(fd);
    println!("send fd {:p} agent {:p}", fd, &agent);

    if amount <= 0 || flags != 0 {
        return PR_FAILURE;
    }
    match agent.write_output(buf as *const u8, amount as usize) {
        Ok(amount) => amount as prio::PRInt32,
        Err(_) => -1,
    }
}

unsafe extern "C" fn agent_available(fd: PrFd) -> prio::PRInt32 {
    let agent = AgentIo::borrow(fd);
    agent.input_available as prio::PRInt32
}

unsafe extern "C" fn agent_available64(fd: PrFd) -> prio::PRInt64 {
    let agent = AgentIo::borrow(fd);
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
