use crate::err::Res;
use crate::p11::{
    PK11SymKey, PK11_Encrypt, PK11_GetBlockSize, PK11_GetMechanism, SECItem, SECItemType, SymKey,
    CKM_AES_ECB, CKM_NSS_CHACHA20_CTR, CK_MECHANISM_TYPE,
};
use crate::result;

use std::os::raw::c_uint;
use std::ptr::null_mut;

/// Generate a header protection mask for QUIC.
pub fn hpmask(key: &SymKey, sample: &[u8]) -> Res<Vec<u8>> {
    let k: *mut PK11SymKey = **key;
    let mech = unsafe { PK11_GetMechanism(k) };
    let block_size = unsafe { PK11_GetBlockSize(mech, null_mut()) } as usize;

    let mut output = vec![0u8; block_size];
    let output_slice = &mut output[..];
    let mut output_len: c_uint = 0;

    let mut item = SECItem {
        type_: SECItemType::siBuffer,
        data: sample.as_ptr() as *mut u8,
        len: sample.len() as c_uint,
    };
    let zero = vec![0u8; block_size];
    let (iv, inbuf) = match () {
        _ if mech == CKM_AES_ECB as CK_MECHANISM_TYPE => (null_mut(), sample),
        _ if mech == CKM_NSS_CHACHA20_CTR as CK_MECHANISM_TYPE => {
            (&mut item as *mut SECItem, &zero[..])
        }
        _ => unreachable!(),
    };
    let rv = unsafe {
        PK11_Encrypt(
            k,
            mech,
            iv,
            output_slice.as_mut_ptr(),
            &mut output_len,
            output.len() as c_uint,
            inbuf.as_ptr() as *const u8,
            inbuf.len() as c_uint,
        )
    };
    result::result(rv)?;
    assert_eq!(output_len as usize, block_size);
    Ok(output)
}
