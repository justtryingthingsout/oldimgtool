// credits to https://github.com/pingw33n/vault13/blob/master/src/fs/dat/lzss.rs

// this whole project's license is GPL because the project I copied it from (the above) is GPL

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::prelude::*;
use std::io::Result;

pub fn lzss_decode_block_content(inp: &mut dyn Read, block_size: u64, out: &mut dyn Write) -> Result<u64> {
    const N: usize = 4096;
    const F: usize = 18;
    const THRESHOLD: usize = 2;

    let mut text_buf = [0x20; N + F - 1];
    let mut r = N - F;
    let mut flags = 0i32;

    let mut block_read = 0u64;
    let mut block_written = 0u64;

    loop {
        flags >>= 1;
        if flags & 0x100 == 0 {
            if block_read >= block_size {
                break;
            }
            let b = inp.read_u8()? as i32;
            block_read += 1;

            if block_read >= block_size {
                break;
            }

            flags = b | 0xff00;
        }

        if (flags & 1) != 0 {
            if block_read >= block_size {
                break;
            }

            let mut i = inp.read_u8()? as usize;
            block_read += 1;

            if block_read >= block_size {
                break;
            }

            let mut j = inp.read_u8()? as usize;
            block_read += 1;

            i |= (j & 0xf0) << 4;
            j = (j & 0x0f) + THRESHOLD;

            for k in 0..=j {
                let b = text_buf[(i + k) & (N - 1)];

                out.write_u8(b)?;
                block_written += 1;

                text_buf[r] = b;
                r = (r + 1) & (N - 1);
            }
        } else {
            let b = inp.read_u8()?;
            block_read += 1;

            out.write_u8(b)?;
            block_written += 1;

            if block_read >= block_size {
                break;
            }

            text_buf[r] = b;
            r = (r + 1) & (N - 1);
        }
    }

    Ok(block_written)
}
