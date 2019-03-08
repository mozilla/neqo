use crate::err::Res;
use crate::p11::{PK11SymKey, PK11_Encrypt, PK11_GetBlockSize, PK11_GetMechanism, SymKey};
use crate::result;

use std::os::raw::c_uint;
use std::ptr::null_mut;

pub fn ecb(key: &SymKey, input: &[u8]) -> Res<Vec<u8>> {
    let k: *mut PK11SymKey = **key;
    let mech = unsafe { PK11_GetMechanism(k) };
    let block_size = unsafe { PK11_GetBlockSize(mech, null_mut()) } as usize;

    let mut output = vec![0u8; block_size];
    let output_slice = &mut output[..];
    let mut output_len: c_uint = 0;
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
    assert_eq!(output_len as usize, block_size);
    Ok(output)
}
