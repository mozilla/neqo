use crate::err::Res;
use crate::p11::{PK11SymKey, PK11_Encrypt, PK11_GetMechanism, SymKey};
use crate::result;

use std::os::raw::c_uint;
use std::ptr::null_mut;

pub fn ecb(key: &SymKey, input: &[u8]) -> Res<Vec<u8>> {
    let k: *mut PK11SymKey = **key;
    let mech = unsafe { PK11_GetMechanism(k) };
    const BLOCK_SIZE: usize = 16; // This is the only block size we support currently.
    let mut output = Vec::with_capacity(BLOCK_SIZE);
    output.resize(BLOCK_SIZE, 0);

    let mut output_len: c_uint = 0;
    let output_slice = &mut output[..];
    let rv = unsafe {
        PK11_Encrypt(
            k,
            mech,
            null_mut(),
            output_slice.as_mut_ptr(),
            &mut output_len,
            output.len() as c_uint,
            input.as_ptr() as *const u8,
            input.len() as c_uint,
        )
    };
    result::result(rv)?;
    assert_eq!(output_len as usize, BLOCK_SIZE);
    Ok(output)
}
