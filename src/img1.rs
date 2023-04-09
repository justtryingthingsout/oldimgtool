use {
    std::fs,
    openssl::{
        symm::{
            Cipher, 
            Crypter, 
            Mode, 
            encrypt
        },
        sha::Sha1,
        rsa::Padding,
        sign::Verifier,
        hash::MessageDigest
    },
    crate::{
        utils::*,
        img2,
        Args
    },
    colored::Colorize,
};


/// # Panics
/// Panics if the input file is not a valid IMG1 file
pub fn create(buf: &[u8], args: &Args, outpath: &str) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = S5LHeader {
        platform: S5L8900_HEADER_MAGIC,
        version: IMG1_FORMAT_1,
        format: 4,
        entry: 0,
        size_of_data: 0,
        footer_sig_off: 0,
        footer_cert_off: 0,
        footer_cert_len: 0,
        salt: [0; 0x20],
        unknown2: 0,
        epoch: 3,
        unencrypted_sig: [0; 4],
        header_signature: [0; 0x10],
        _pad: [0; 0x7B0],
    };

    let (mut sig, mut cert) = (None, None);
    let img2 = &img2::create(buf, args);

    if let Some(sigpath) = &args.sigpath {
        sig = Some(fs::read(sigpath).unwrap());
        assert_eq!(sig.as_ref().unwrap().len(), 0x80);
        objh.footer_sig_off = cast_force!(img2.len(), u32);
    }

    if let Some(certpath) = &args.certpath {
        cert = Some(fs::read(certpath).unwrap());
        let certlen = cert.as_ref().unwrap().len();
        objh.footer_cert_off = objh.footer_sig_off + 0x80;
        objh.footer_cert_len = cast_force!(certlen, u32);
    }
    
    objh.size_of_data = cast_force!(img2.len(), u32);

    struct_write!(objh, newimg);
    newimg.extend_from_slice(img2);

    let mut sha1 = Sha1::new();
    sha1.update(&newimg[0..0x40]);
    let res = &sha1.finish()[0..0x10];
    let cipher = Cipher::aes_128_cbc();
    let encd = &encrypt(
        cipher, 
        KEY_0x837, 
        None,
        res
    ).unwrap_or_else(|e| 
        panic!("{} to encrypt img2 sha1, error: {e}", "Failed".red())
    )[0..0x10];
    objh.header_signature = encd.try_into().unwrap();

    struct_write!(objh, newimg);

    if let Some(sig) = sig {
        newimg.extend_from_slice(&sig);
    }
    if let Some(cert) = cert {
        newimg.extend_from_slice(&cert);
    }
    write_file(outpath, &newimg);
}

/// # Panics
/// Panics if the input file is not a valid IMG1 file
pub fn parse(file: &[u8], args: &Args) {
    let mut head = cast_struct!(S5LHeader, file);
    if args.all {
        println!("{head}");
    }
    
    let mut is_valid = true;

    let is_ios = head.platform == S5L8900_HEADER_MAGIC || (head.platform == S5L8720_HEADER_MAGIC && head.version == IMG1_FORMAT_1);

    let cipher = Cipher::aes_128_cbc();
    let datstart = if head.platform == S5L8900_HEADER_MAGIC || head.platform == S5L8702_HEADER_MAGIC {
        0x800
    } else {
        0x600
    };

    if let Some(path) = &args.savesigpath {
        assert!(datstart + head.footer_sig_off as usize != file.len(), "Signature does not exist!");
        write_file(path, &file[datstart + head.footer_sig_off as usize..datstart + head.footer_cert_off as usize]);
    }
    if let Some(path) = &args.savecertpath {
        assert!(datstart + head.footer_cert_off as usize != file.len(), "Certificate chain does not exist!");
        write_file(path, &file[range_size(datstart + head.footer_cert_off as usize, head.footer_cert_len as usize)]);
    }

    let mut bufkey = None;
    if let Some(ref key) = args.key {
        bufkey = hex::decode(key).ok();
    } else if head.platform == S5L8900_HEADER_MAGIC || (head.platform == S5L8720_HEADER_MAGIC && head.version == IMG1_FORMAT_1) {
        bufkey = Some(KEY_0x837.to_vec());
    }

    if head.format == X509_SIGNED_ENCRYPTED {
        if let Some(ref key) = bufkey {
            let mut decrypter = Crypter::new(
                cipher,
                Mode::Decrypt,
                key,
                None
            ).unwrap();
            decrypter.pad(false);
            let mut decry = vec![0; head.size_of_data as usize + cipher.block_size()];
            let count = decrypter.update(
                &file[range_size(datstart, head.size_of_data as usize)], 
                &mut decry
            ).unwrap();
            decrypter.finalize(&mut decry).unwrap();
            decry.truncate(count);

            if let Some(path) = &args.outfile {
                if args.dec {
                    let mut newfile = file.to_owned();
                    head.format = X509_SIGNED;
                    struct_write!(head, newfile);
                    newfile[range_size(datstart, head.size_of_data as usize)].copy_from_slice(&decry);
                    write_file(path, &newfile);
                } else if args.img2 {
                    write_file(path, &decry);
                }
            }
            img2::parse(&decry, args, &mut is_valid, &None);
        } else if let Some(path) = &args.outfile {
            println!("Extracting encrypted data...");
            write_file(path, &file[range_size(datstart, head.size_of_data as usize)]);
        }
    } else {
        if is_ios {
            img2::parse(&file[range_size(datstart, head.size_of_data as usize)], args, &mut is_valid, &None);
        }
        if let Some(path) = &args.outfile {
            if args.img2 || !is_ios {
                write_file(path, &file[range_size(datstart, head.size_of_data as usize)]);
            }
        }
    }

    if args.verify {
        if is_ios {
            let mut sha1 = Sha1::new();
            sha1.update(&file[0..0x40]);
            let res = &sha1.finish()[0..0x10];
            let encd = &encrypt(
                cipher, 
                KEY_0x837, 
                None,
                res
            ).unwrap_or_else(|e| 
                panic!("{} to encrypt S5L SHA1, error: {e}", "Failed".red())
            )[0..0x10];

            println!("Header signature is {}", 
                     if encd == head.header_signature {
                         "correct".green()
                     } else {
                         is_valid = false;
                         "incorrect".red()
                     }
            );
        } else {
            println!("Entire S5L header signature cannot be verified without decryption, but trying with unencrypted left over signature anyways...");
            let mut sha1 = Sha1::new();
            sha1.update(&file[0..0x40]);
            let res = &sha1.finish()[0x10..];
            println!("Partial Header signature is {}", 
                     if res == head.unencrypted_sig {
                         "correct".green()
                     } else {
                         is_valid = false;
                         "incorrect".red()
                     }
            );
        }

        let mut i = head.footer_cert_off as usize + datstart;
        let mut certs: Vec<X509> = Vec::new();
        while i < datstart + (head.footer_cert_off + head.footer_cert_len) as usize  {
            let check = u16::from_be_bytes(file[range_size(i, 2)].try_into().unwrap());
            assert_eq!(check, 0x3082);
            let len = u16::from_be_bytes(file[range_size(i + 2, 2)].try_into().unwrap()) as usize;
            certs.push(X509::from_der(&file[range_size(i, 4 + len)]).unwrap());
            i += 4 + len;
        }

        let mut certiter = certs.iter().enumerate();
        println!("Assuming \"{}\" is trusted", get_cn(certiter.next().unwrap().1));

        for (j, cert) in certiter {
            let cn = get_cn(cert);
            match cert.verify(&certs[j - 1].public_key().unwrap()) {
                Ok(_) => println!("Certificate \"{cn}\" is {}", "valid".green()),
                Err(e) => {
                    println!("{} verification of \"{cn}\" with error: {e}", "Failed".red());
                    is_valid = false;
                },
            }
        }

        if datstart + head.footer_sig_off as usize == file.len() {
            println!("No image signature to verify, assuming it is valid");
        } else {
            let leafpub = certs[certs.len()-1].public_key().unwrap();
            let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
            verifier.set_rsa_padding(Padding::PKCS1).unwrap();
            verifier.update(&file[0..datstart + head.size_of_data as usize]).unwrap();
            let ok = verifier.verify(&file[range_size(datstart + head.footer_sig_off as usize, 0x80)]).unwrap();
            println!("S5L file signature {}", 
                if ok {
                    "matches".green()
                } else {
                    is_valid = false;
                    "does not match".red()
                }
            );
        }
        println!("This image is {}", 
                if is_valid {
                    "valid".green()
                } else {
                    "invalid".red()
                }
        );
    }
}