use {
    crate::{
        Args, 
        utils::*,
    },
    binrw::BinReaderExt,
    colored::Colorize,
    crc32fast::hash,
    openssl::symm::{
        Cipher, 
        Crypter, 
        Mode, 
    }
};

/// # Panics
/// Panics if the file is not an IMG2 file, if the keys are invalid, or the arguments are invalid.
pub fn parse(file: &[u8], args: &Args, is_valid: &mut bool, key: &Option<Vec<u8>>) {
    if file[0..4] != IMG2_HEADER_CIGAM { return }
    let head = cast_struct!(IMG2Header, file);
    if args.all {
        println!("{head}");
    }
    if !args.all && args.imgtype {
        println!("Image type: {}", revstr_from_le_bytes(&head.img_type));
    }

    if let Some(path) = &args.outfile {
        if !args.dec && !args.img2 {
            let dataoff = 0x400;
            if let Some(ref key) = key {
                if head.opts & IMG2_OPT_ENCRYPTED_IMAGE != 0 {
                    let cipher = Cipher::aes_128_cbc();
                    let mut decrypter = Crypter::new(
                        cipher,
                        Mode::Decrypt,
                        key,
                        None
                    ).unwrap();
                    decrypter.pad(false);
                    let mut decry = vec![0; head.data_size as usize + cipher.block_size()];
                    let count = decrypter.update(
                        &file[range_size(dataoff, head.data_size as usize)],
                        &mut decry
                    ).unwrap();
                    decrypter.finalize(&mut decry).unwrap();
                    decry.truncate(count);
                    write_file(path, &decry);
                }
            } else {
                write_file(path, &file[range_size(dataoff, head.data_size as usize)]);
            }
        }
    }
    
    if args.verify {
        println!("Header CRC32 is {}", 
                if hash(&file[0..0x64]) == head.header_crc32 {
                    "correct".green()
                } else {
                    *is_valid = false;
                    "incorrect".red()
                }
        );

        /*
            Data signature cannot be verified without a UID encrypted IMG2 Verify key
            The verify key is 
                {0xCD, 0xF3, 0x45, 0xB3, 0x12, 0xE7, 0x48, 0x85, 0x8B, 0xBE, 0x21, 0x47, 0xF0, 0xE5, 0x80},
            encrypted with the UID, with the IV as 
                {0x41, 0x70, 0x5D, 0x11, 0x6F, 0x98, 0x4B, 0x82, 0x9C, 0x6C, 0x99, 0xBB, 0xA5, 0xF1, 0x78, 0x69}.

            Once encrypted, the signature can be verified by 
                1. taking a SHA1 digest of 0x400 ~ 0x400 + data size
                2. padding it with the IMG2 Hash Padding, which is 
                    { 0xAD, 0x2E, 0xE3, 0x8D, 0x2D, 0x9B, 0xE4, 0x35, 0x99, 4,
					  0x44, 0x33, 0x65, 0x3D, 0xF0, 0x74, 0x98, 0xD8, 0x56, 0x3B,
					  0x4F, 0xF9, 0x6A, 0x55, 0x45, 0xCE, 0x82, 0xF2, 0x9A, 0x5A,
					  0xC2, 0xBC, 0x47, 0x61, 0x6D, 0x65, 0x4F, 0x76, 0x65, 0x72,
					  0xA6, 0xA0, 0x99, 0x13 }, until the buffer is 0x40 bytes long
                3. Encrypting the SHA1 digest with the UID encrypted IMG2 Verify key
                4. Comparing it against the signature

            The same can be done for the 0x20 byte long hash at 0x3E0 (except padding only to 0x20), 
            which is the hash of 0 ~ 0x3E0.
        */
    }
    
    let mut extoff = 0x68;
    let mut extsize: usize = head.extsize as usize;
    if head.opts & IMG2_OPT_EXTENSION_PRESENT != 0 || head.extsize != 0xFFFF_FFFF {
        if head.opts & IMG2_OPT_EXTENSION_PRESENT == 0 && (args.verify || args.all) {
            println!("Extension header found even through extension option is not set. Will parse anyways...");
        }
        loop {
            let exthead = cast_struct_args!(IMG2ExtHeader, &file[extoff..], (head.extsize, ));
            if args.all {
                println!("{exthead}");
            }
            if !args.all && args.ver {
                println!("Version string: {}", from_utf8(&exthead.data).unwrap());
            }
            if args.verify {
                println!("Extension Header \"{}\" CRC32 is {}", 
                          revstr_from_le_bytes(&exthead.ext_type),
                          if hash(&file[range_size(extoff + 4, 12 + extsize)]) == exthead.check {
                            "correct".green()
                          } else {
                            *is_valid = false;
                            "incorrect".red()
                          }
                );
            }
            if exthead.next_size == 0xFFFF_FFFF {
                break;
            }
            extsize = exthead.next_size as usize;
            extoff += 16 + extsize;
        }
    }
} 

/// # Panics
/// Panics if the arguments in Args are invalid
#[must_use] pub fn create(buf: &[u8], args: &Args) -> Vec<u8> {
    let mut newimg: Vec<u8> = Vec::new();
    let mut type_4cc = [0; 4];
    if let Some(ref settype) = args.settype {
        assert!(settype.len() == 4, "Type length is not 4");
        type_4cc = settype.as_bytes().try_into().unwrap();
    }
    let mut objh = IMG2Header {
        magic:           IMG2_HEADER_CIGAM,
        img_type:        type_4cc,
        sec_epoch:       3,
        load_addr:       0x1800_0000,
        data_size:       cast_force!(buf.len(), u32),
        decry_data_size: cast_force!(buf.len(), u32),
        alloc_size:      u32::MAX,
        extsize:         u32::MAX,
        ..Default::default()
    };

    if let Some(imgtype) = &args.settype {
        assert!(imgtype.len() == 4, "Type length is not 4");
        objh.img_type = imgtype.as_bytes().try_into().unwrap();
    }
    if let Some(ver) = &args.setver {
        let fr = ver.as_bytes().to_owned();
        let mut ext = IMG2ExtHeader {
            next_size: u32::MAX,
            ext_type: *b"vers",
            data: fr,
            ..Default::default()
        };
        objh.extsize = cast_force!(ext.data.len(), u32);
        struct_write!(ext, newimg[0x68..]);
        ext.check = hash(&newimg[range_size(0x6C, 12+ext.data.len())]);
        struct_write!(ext, newimg[0x68..]);
    }
    struct_write!(objh, newimg);
    objh.header_crc32 = hash(&newimg[0..0x64]);
    struct_write!(objh, newimg);
    newimg.extend_from_slice(&[0; 0x398]); //padding to 0x400
    newimg.extend_from_slice(buf);
    newimg
}