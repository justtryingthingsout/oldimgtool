#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use {
    bindings::*,
    crate::utils::{LZSSHead, LZSS_MAGIC},
};

/// # Safety
/// data.len() must be less than or equal to the actual data size
#[must_use] pub fn create_complzss_header(data: &[u8], comp_data: Vec<u8>) -> LZSSHead {
    let datptr = data.as_ptr();
    let adler32 = unsafe { 
        //SAFETY: so long as data.len() is <= to the actual data size, this should be safe, undefined behavior otherwise
        local_adler32(datptr, cast_force!(data.len(), i32))
    };
    LZSSHead {
        magic: LZSS_MAGIC,
        adler32,
        decomp_len: cast_force!(data.len(), u32),
        comp_len: cast_force!(comp_data.len(), u32),
        vers: 1,
        pad: vec![0; 360],
        comp_data
    }
}

/// # Safety
/// data must be a valid LZSS compressed file
/// len must be the length of the decompressed data (or bigger)
/// # Panics
/// Panics if the decompressed data is larger than the allocated buffer, meaning lzss wrote beyond the buffer
#[must_use] pub fn decompress(data: &[u8], len: u32, adler32: u32) -> Option<Vec<u8>> {
    let mut decmpvec = Vec::with_capacity(len as usize);
    let sz = cast_force!(unsafe { 
        decompress_lzss(decmpvec.as_mut_ptr(), len, data.as_ptr(), cast_force!(data.len(), u32)) 
    }, u32);
    assert!(sz <= len, "LZSS decompressor wrote beyond allocated buffer"); //program is no longer stable, crash (this should never happen)
    unsafe { decmpvec.set_len(cast_force!(sz, usize)); }
    unsafe { local_adler32(decmpvec.as_ptr(), cast_force!(len, i32)) }.eq(&adler32).then_some(decmpvec)
}

/// # Panics
/// Panics if the compressed data is larger than the allocated buffer, meaning lzss wrote beyond the buffer
#[must_use] pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut cmpvec = Vec::with_capacity(data.len());
    let cmpvecptr = cmpvec.as_mut_ptr();
    let outptr = unsafe { compress_lzss(cmpvecptr, cast_force!(cmpvec.capacity(), u32), data.as_ptr(), cast_force!(data.len(), u32)) };
    let sz = outptr as usize - cmpvecptr as usize;
    assert!(sz <= data.len(), "LZSS compressor wrote beyond allocated buffer"); //program is no longer stable, crash (this should never happen)
    unsafe { cmpvec.set_len(sz); }
    cmpvec
}