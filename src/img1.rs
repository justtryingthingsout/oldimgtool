/*
    oldimgtool - A IMG1/2/3 parser and a NOR dump parser
    Copyright (C) 2024 plzdonthaxme

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
        utils::{
            BinReaderExt,
            BinWrite,
            Cursor,
            FromDer,
            LZSSHead,
            LZSS_MAGIC,
            IMG1_FORMAT_1,
            KEY_837,
            S5L8442_HEADER_MAGIC,
            S5L8443_HEADER_MAGIC,
            S5L8702_HEADER_MAGIC,
            S5L8720_HEADER_MAGIC,
            S5L8723_HEADER_MAGIC,
            S5L8730_HEADER_MAGIC,
            S5L8740_HEADER_MAGIC,
            S5L8900_HEADER_MAGIC,
            S5LHeader,
            Sequence,
            X509_SIGNED,
            X509_SIGNED_ENCRYPTED,
            range_size,
            verify_cert,
            write_file
        },
        img2,
        lzss,
        Args
    },
    colored::Colorize
};


/// # Panics
/// Panics if the input file is not a valid IMG1 file
pub fn create(buf: &[u8], args: &Args) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = S5LHeader {
        platform: S5L8900_HEADER_MAGIC,
        version: IMG1_FORMAT_1,
        format: 4,
        salt: [0; 0x20],
        epoch: 3,
        ..Default::default()
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
        KEY_837, 
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
    write_file(args.outfile.as_ref().unwrap(), &newimg);
}

/// # Panics
/// Panics if the input file is not a valid IMG1 file
#[expect(clippy::too_many_lines, clippy::cognitive_complexity)] // refactor required
pub fn parse(file: &[u8], args: &Args) {
    let mut head = cast_struct!(S5LHeader, file);
    if args.all {
        println!("{head}");
    }
    
    let mut is_valid = true;

    let is_ios = head.platform == S5L8900_HEADER_MAGIC || (head.platform == S5L8720_HEADER_MAGIC && head.version == IMG1_FORMAT_1);

    let cipher = Cipher::aes_128_cbc();
    let datstart = if head.platform == S5L8900_HEADER_MAGIC || head.platform == S5L8702_HEADER_MAGIC || head.platform == S5L8442_HEADER_MAGIC {
        0x800
    } else if head.platform == S5L8720_HEADER_MAGIC || head.platform == S5L8730_HEADER_MAGIC {
        0x600
    } else if head.platform == S5L8723_HEADER_MAGIC || head.platform == S5L8740_HEADER_MAGIC || head.platform == S5L8443_HEADER_MAGIC {
        0x400
    } else {
        0x800 //idk
    };

    let lenalign = (head.size_of_data + 0xF) & !0xF;
    let sig_off = datstart + if head.footer_sig_off < lenalign + 0x300 { // 8900 case
         head.footer_sig_off as usize
    } else { //newer iPod case
        /* supposed to be `if head.footer_cert_off < lenalign + 0x80`,
           but iPod bootroms ignore it anyways */
        lenalign as usize
    };

    if let Some(path) = &args.savesigpath {
        assert!(sig_off != file.len(), "Signature does not exist!");
        write_file(path, &file[range_size(sig_off, 0x80)]);
    }
    if let Some(path) = &args.savecertpath {
        assert!(datstart + head.footer_cert_off as usize != file.len(), "Certificate chain does not exist!");
        write_file(path, &file[range_size(datstart + head.footer_cert_off as usize, head.footer_cert_len as usize)]);
    }

    let mut bufkey = None;
    if let Some(ref key) = args.key {
        bufkey = hex::decode(key).ok();
    } else if head.platform == S5L8900_HEADER_MAGIC || (head.platform == S5L8720_HEADER_MAGIC && head.version == IMG1_FORMAT_1) {
        bufkey = Some(KEY_837.to_vec());
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
            let mut decry = vec![0; head.size_of_data as usize + cipher.block_size()]; //requires size_of_data aligned?
            let count = decrypter.update(
                &file[range_size(datstart, head.size_of_data as usize)],  //requires size_of_data aligned?
                &mut decry
            ).unwrap();
            decrypter.finalize(&mut decry).unwrap();
            decry.truncate(count);

            if let Some(path) = &args.outfile {
                if args.dec {
                    let mut newfile = file.to_owned();
                    head.format = X509_SIGNED;
                    struct_write!(head, newfile);
                    newfile[range_size(datstart, head.size_of_data as usize)].copy_from_slice(&decry); //requires size_of_data aligned?
                    write_file(path, &newfile);
                } else if args.img2 {
                    write_file(path, &decry);
                } else if decry[..8] == LZSS_MAGIC {
                    let lzsstr = cast_struct!(LZSSHead, &decry);
                    let decomp = lzss::decompress(&lzsstr.comp_data, lzsstr.decomp_len, lzsstr.adler32)
                        .expect("LZSS did not contain valid data!");
                    write_file(path, &decomp);
                } 
            }
            img2::parse(&decry, args, &mut is_valid, &None);
        } else if let Some(path) = &args.outfile {
            println!("Extracting encrypted data...");
            write_file(path, &file[range_size(datstart, head.size_of_data as usize)]); //requires size_of_data aligned?
        }
    } else {
        if is_ios {
            img2::parse(&file[range_size(datstart, head.size_of_data as usize)], args, &mut is_valid, &None); //requires size_of_data aligned?
        }
        if let Some(path) = &args.outfile {
            if file[range_size(datstart, 8)] == LZSS_MAGIC {
                let lzsstr = cast_struct!(LZSSHead, &file[range_size(datstart, head.size_of_data as usize)]);
                let decomp = lzss::decompress(&lzsstr.comp_data, lzsstr.decomp_len, lzsstr.adler32)
                    .expect("LZSS did not contain valid data!");
                write_file(path, &decomp);
            } else if args.img2 || !is_ios {
                write_file(path, &file[range_size(datstart, head.size_of_data as usize)]); //requires size_of_data aligned?
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
                KEY_837, 
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
        } else if head.unencrypted_sig != [0; 4] {
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
        } else {
            println!("S5L header signature cannot be verified");
        }

        let i = head.footer_cert_off as usize + datstart;
        let check = Sequence::from_der(&file[i..]);
        if check.is_ok() && file.len() >= i + head.footer_cert_len as usize {
            let leafcert = verify_cert(&file[range_size(i, head.footer_cert_len as usize)], &mut is_valid);

            if sig_off == 0 {
                println!("No image signature to verify, assuming it is valid");
            } else {
                let leafpub = leafcert.public_key().unwrap();
                let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                verifier.update(&file[0..sig_off]).unwrap();
                let ok = verifier.verify(&file[range_size(sig_off, 0x80)]).unwrap();
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
        } else {
            println!("Found cert section with invalid certificates, skipping verification");
        }
    }
}