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
            let dataoff = 0x68 + //IMG2 header size
                          if head.opts & IMG2_OPT_EXTENSION_PRESENT == 0 {0} else {
                            0x10 + //Extension header size
                            head.extsize as usize + //Extension data size
                            0x1 //Pad (0xFF byte)
                          } + 0x378; //Padding
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
    }
    
    let mut extoff = 0x68;
    let mut extsize: usize = head.extsize as usize;
    if head.opts & IMG2_OPT_EXTENSION_PRESENT != 0 || head.extsize != 0xFFFF_FFFF {
        if head.extsize != 0xFFFF_FFFF && (args.verify || args.all) {
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
        revision:        0,
        sec_epoch:       3,
        load_addr:       0x1800_0000,
        data_size:       cast_force!(buf.len(), u32),
        decry_data_size: cast_force!(buf.len(), u32),
        alloc_size:      u32::MAX,
        opts:            0,
        sig_data:        [0; 0x40],
        extsize:         u32::MAX,
        header_crc32:    0,
    };

    if let Some(imgtype) = &args.settype {
        assert!(imgtype.len() == 4, "Type length is not 4");
        objh.img_type = imgtype.as_bytes().try_into().unwrap();
    }
    if let Some(ver) = &args.setver {
        let fr = ver.as_bytes().to_owned();
        let mut ext = IMG2ExtHeader {
            check: 0,
            next_size: u32::MAX,
            ext_type: *b"vers",
            opt: 0,
            data: fr,
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