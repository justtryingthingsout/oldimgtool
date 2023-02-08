#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;

use crate::utils::LZSSHead;

pub fn create_complzss_header(data: &[u8], comp_data: Vec<u8>) -> LZSSHead {
    let datptr = data.as_ptr();
    let adler32 = unsafe { 
        //SAFETY: so long as data.len() is <= to the actual data size, this should be safe, undefined behavior otherwise
        local_adler32(datptr, data.len().try_into().unwrap())
    };
    LZSSHead {
        magic: *b"complzss",
        adler32,
        decomp_len: data.len() as u32,
        comp_len: comp_data.len() as u32,
        unk: 1,
        pad: vec![0; 360],
        comp_data
    }
}

pub fn decomp_lzss(data: &[u8], len: u32, adler32: u32) -> Option<Vec<u8>> {
    let mut decmpvec = Vec::with_capacity(len as usize);
    let sz: u32 = unsafe { decompress_lzss(decmpvec.as_mut_ptr(), len, data.as_ptr(), data.len() as u32) }.try_into().unwrap();
    assert!(sz <= len, "LZSS compress wrote beyond allocated buffer"); //program is no longer stable, crash (this should never happen)
    if unsafe { local_adler32(decmpvec.as_ptr(), len.try_into().unwrap()) } != adler32 { 
        None
    } else {
        Some(decmpvec)
    }
}

pub fn comp_lzss(data: &[u8]) -> Vec<u8> {
    let mut cmpvec = Vec::with_capacity(data.len());
    let cmpvecptr = cmpvec.as_mut_ptr();
    let outptr = unsafe { compress_lzss(cmpvecptr, cmpvec.capacity() as u32, data.as_ptr(), data.len() as u32) };
    let sz = outptr as usize - cmpvecptr as usize;
    assert!(sz <= data.len(), "LZSS decompress wrote beyond allocated buffer"); //program is no longer stable, crash (this should never happen)
    unsafe { cmpvec.set_len(sz); }
    cmpvec
}