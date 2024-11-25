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
    crate::{
        apticket, utils::{
            checkvalid_decry, compress, create_complzss_header, do_resize, override_types, print_unknown_val, range_size, revstr_from_le_bytes, verify_cert, write_file, BinWrite, Cursor, DeviceInfo, IMG3ObjHeader, IMG3TagHeader, IMG3TagString, IMG3KBAG, IMG3_GAT_CERTIFICATE_CHAIN, IMG3_GAT_DATA, IMG3_GAT_KEYBAG, IMG3_GAT_RANDOM, IMG3_GAT_SIGNED_HASH, IMG3_GAT_TYPE, IMG3_GAT_UNIQUE_ID, IMG3_GAT_VERSION, IMG3_HEADER_CIGAM, IMG3_TAG_BAT0, IMG3_TAG_BAT1, IMG3_TAG_BATF, IMG3_TAG_BOARD_TYPE, IMG3_TAG_CERT, IMG3_TAG_CERTIFICATE_CHAIN, IMG3_TAG_CHG0, IMG3_TAG_CHG1, IMG3_TAG_CHIP_TYPE, IMG3_TAG_DATA, IMG3_TAG_DIAG, IMG3_TAG_DTRE, IMG3_TAG_GLYC, IMG3_TAG_GLYP, IMG3_TAG_HARDWARE_EPOCH, IMG3_TAG_IBEC, IMG3_TAG_IBOT, IMG3_TAG_IBSS, IMG3_TAG_ILLB, IMG3_TAG_KEYBAG, IMG3_TAG_KRNL, IMG3_TAG_LOGO, IMG3_TAG_NONCE, IMG3_TAG_OVERRIDE, IMG3_TAG_PRODUCTION_STATUS, IMG3_TAG_RANDOM, IMG3_TAG_RANDOM_PAD, IMG3_TAG_RDSK, IMG3_TAG_RDTR, IMG3_TAG_RECM, IMG3_TAG_RKRN, IMG3_TAG_RLGO, IMG3_TAG_SCAB, IMG3_TAG_SECURITY_DOMAIN, IMG3_TAG_SECURITY_EPOCH, IMG3_TAG_SIGNED_HASH, IMG3_TAG_TYPE, IMG3_TAG_UNIQUE_ID, IMG3_TAG_VERSION
        }, Args
    }, asn1_rs::{
        FromDer, 
        OctetString, 
        Sequence
    }, binrw::BinReaderExt, colored::Colorize, openssl::{
        hash::MessageDigest, rsa::Padding, sha::sha1, sign::Verifier, symm::{
            encrypt, Cipher, Crypter, Mode
        }, x509::X509
    }, plist::Value, std::{
        borrow::Cow, fs, io::Read, result::Result
    }
};

fn parse_ext(leafcert: &X509, args: &mut Args, is_valid: &mut bool, devinfo: &mut Option<DeviceInfo>) -> bool {
    unsafe {
        /* 
        * openssl crate does not implement the below functions, 
        * use unsafe to call the openssl_sys versions ourselves and check for errors 
        */
        use openssl_sys::{
            OBJ_txt2obj, //NID_undef, OBJ_obj2nid, OBJ_create, 
            d2i_X509, X509_free, X509_get_ext_by_OBJ, X509_get_ext, 
            X509_EXTENSION_get_data,
            ASN1_STRING, ASN1_STRING_length, ASN1_STRING_get0_data,
            ERR_get_error, ERR_reason_error_string
        };
        use std::{
            ffi::{CString, CStr},
            ptr::{null_mut, addr_of_mut}, // null,
            slice::from_raw_parts
        };

        let leafder = leafcert.to_der().unwrap();
        let mut x509_loc_ptr = leafder.as_ptr();
        let unsafe_x509_cert = d2i_X509(null_mut(), addr_of_mut!(x509_loc_ptr), leafder.len().try_into().unwrap());
        assert!(!unsafe_x509_cert.is_null(), "Failed to parse X509");

        //CFTypeRef kSecOIDAPPLE_EXTENSION_APPLE_SIGNING = CFSTR("1.2.840.113635.100.6.1.1");
        let as_obj_id = CString::new("1.2.840.113635.100.6.1.1").unwrap();
        //let as_short  = CString::new("APPLE_SIGNING").unwrap();
        //let as_long   = CString::new("APPLE_EXTENSION_APPLE_SIGNING").unwrap();
        //let as_nid    = OBJ_create(as_obj_id.as_ptr(), null(), null());
        let as_obj = OBJ_txt2obj(as_obj_id.as_ptr(), 1);
        if as_obj.is_null() {
            let err = ERR_get_error();
            assert!(err != 0);
            let errstr = ERR_reason_error_string(err);
            let errstr = CStr::from_ptr(errstr);
            panic!("Failed to create NID with error: {}", errstr.to_str().unwrap());
        }

        let nid_idx = X509_get_ext_by_OBJ(unsafe_x509_cert, as_obj, -1);
        //assert!(nid_idx != -1, "Failed to get signing extension!");
        if nid_idx == -1 {
            return false;
        }
        println!("Found Apple certificate signing extension, parsing it");
        let ext     = X509_get_ext(unsafe_x509_cert, nid_idx);
        assert!(!ext.is_null(), "Failed to get extension");
        
        let val     = X509_EXTENSION_get_data(ext) as *const ASN1_STRING; // infallable according to docs
        let len     = ASN1_STRING_length(val);    // infallable according to docs
        let dataptr = ASN1_STRING_get0_data(val); // infallable according to docs
        let asn1_slice = from_raw_parts(dataptr, len.try_into().unwrap());
        let img3_octet = OctetString::from_der(asn1_slice).unwrap().1;
        let img3_slice = img3_octet.as_cow();

        assert_eq!(img3_slice[0..4], IMG3_HEADER_CIGAM, "Apple certificate signing extension does not contain IMG3 data");
        args.verify = false;
        parse(img3_slice.to_vec(), args, is_valid, devinfo);
        args.verify = true;
        X509_free(unsafe_x509_cert);
        true
    } //end unsafe
}

fn cert_tag(args: &mut Args, 
            head: &IMG3ObjHeader, taghead: &IMG3TagHeader, 
            file: &[u8], shshdata: &[u8], 
            is_valid: &mut bool, 
            devinfo: &mut Option<DeviceInfo>) -> bool {

    if args.verify {
        let check = Sequence::from_der(&taghead.buf[0..]);
        if check.is_ok() {
            let leafcert = verify_cert(&taghead.buf, is_valid);
            let has_ext = parse_ext(&leafcert, args, is_valid, devinfo);

            let leafpub = leafcert.public_key().unwrap();

            let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
            verifier.set_rsa_padding(Padding::PKCS1).unwrap();
            verifier.update(&file[12..20 + head.signed_len as usize]).unwrap();
            let ok = verifier.verify(shshdata).unwrap();
            println!("IMG3 file signature is {}", 
                    if ok {
                        "valid".green()
                    } else {
                        *is_valid = false;
                        "invalid".red()
                    }
            );
            if let Some(devinfo) = devinfo {
                if has_ext {
                    if devinfo.sdom.is_none() || devinfo.prod.is_none() || devinfo.cpid.is_none() {
                        println!("Required constraints do not exist in the certificate extension, marking this image invalid.");
                        *is_valid = false;
                    }
                } else {
                    println!("No extension found, assuming old iBoot component");
                }
            }
            println!("This image is {}{}", 
                    if *is_valid {
                        "valid".green()
                    } else {
                        "invalid".red()
                    },
                    if *is_valid { // no point showing the info if it's invalid anyways
                        devinfo
                            .as_mut()
                            .map_or_else(
                                || Cow::from(" without constraints"), 
                                |devinfo| Cow::from(devinfo.to_string())
                            )
                    } else {
                        Cow::from("")
                    }
            );
            return true;
        }
        println!("Found a CERT tag with invalid certificates, skipping verification");
        return true;
    };
    false
}

fn data_tag(args: &mut Args, head: &mut IMG3ObjHeader, taghead: &mut IMG3TagHeader, file: &mut Vec<u8>, i: usize) {
    if let Some(datapath) = &args.setdata {
        let mut datafile = fs::read(datapath).unwrap();
        if args.comp {
            let lzsscomp = compress(&datafile);
            let compsz = lzsscomp.len();
            let lzsshead = create_complzss_header(&datafile, lzsscomp);
            struct_write!(lzsshead, datafile);
            datafile.truncate(384 + compsz);
        }
        let taglen = 12 + cast_force!(taghead.buf.len() + taghead.pad.len(), u32);
        do_resize(head, taghead, file, i, taglen, datafile);
        args.dec = true; //hack to remove keybag headers
    }

    if let (Some(argkey), Some(path)) = (args.key.as_deref(), args.outfile.as_deref()) {  
        let mut undec = Vec::new();
        let mut key = argkey;
        let iv = args.iv.as_deref().unwrap_or_else(|| {
            let ret = &argkey[..32];
            key = &argkey[32..];
            ret
        });
        let key_bytes = hex::decode(key.as_bytes()).unwrap();
        let iv_bytes  = hex::decode(iv.as_bytes()).unwrap();
        
        let cipher = match key.len() {
            32 => Cipher::aes_128_cbc(),
            48 => Cipher::aes_192_cbc(),
            64 => Cipher::aes_256_cbc(),
            x => panic!("Invalid key size: {x}")
        };

        let is_old = taghead.pad.bytes().filter_map(Result::ok).all(|b| b == 0); // just a guess for <= iPhoneOS 3.0
        if is_old {
            let rem = taghead.buf.len() % cipher.block_size();
            if rem != 0 {
                undec = taghead.buf.drain((taghead.buf.len() - rem)..).collect();
            }
        } else {
            taghead.buf.append(&mut taghead.pad);
        }

        let mut decrypter = Crypter::new(
            cipher,
            Mode::Decrypt,
            &key_bytes,
            Some(&iv_bytes)
        ).unwrap();
        decrypter.pad(false);
        let mut buf = vec![0; taghead.buf.len() + cipher.block_size()];
        decrypter.update(
            &taghead.buf, 
            &mut buf
        ).unwrap();
        let mut flag = true;
        decrypter.finalize(&mut buf).unwrap_or_else(|e| {
            use std::io::Write;
            let errstack = e.errors();
            let cond = errstack.len() > 1;
            print!("Got {} whilst finalizing the decryption: ", 
                if cond { "multiple errors" } else { "an error" }
            );
            if cond {
                for err in &errstack[..(errstack.len()-1)] {
                    print!("{}, ", 
                        err.reason().unwrap_or("No reason given")
                    );
                }
            }
            println!("{}", 
                errstack.last().unwrap().reason().unwrap_or("No reason given")
            );

            print!("This can sometimes still contain valid data, continue? [y/N]: ");
            std::io::stdout().flush().unwrap();
            let mut opt = String::new();
            std::io::stdin().read_line(&mut opt).unwrap();
            if opt.trim() != "y" { 
                flag = false;
            };
            0
        });
        if flag {
            buf.truncate((buf.len() - cipher.block_size()) as usize);
            if is_old {
                buf.append(&mut undec);
            }
            
            if args.dec {
                taghead.buf = buf;
                struct_write!(taghead, file[i..]);
            } else {
                write_file(path, &checkvalid_decry(&buf, head.img3_type, args.ext).unwrap_or(buf));
            }
        }
    } else if let Some(path) = &args.outfile {
        // if img3 setters are used, it wouldn't make sense to output the data buffer
        if args.setdata.is_none() 
        && args.setver.is_none() 
        && args.setkbag.is_none() 
        && args.settype.is_none()
        && args.sigpath.is_none()
        && args.certpath.is_none()
        && args.shshpath.is_none() {
            write_file(path, &checkvalid_decry(&taghead.buf, head.img3_type, args.ext).unwrap_or_else(|| taghead.buf.clone()));
        }
    }
}

fn kbag_tag(args: &Args, mainhead: &mut IMG3ObjHeader, taghead: &mut IMG3TagHeader, file: &mut Vec<u8>, i: usize, data: usize) -> bool{
    let mut keyhead = cast_struct!(IMG3KBAG, &taghead.buf);
    if args.all || args.keybags {
        println!("\tKey type: {}", match keyhead.selector {
            0 => String::from("Unencrypted Key"),
            1 => String::from("Production-fused Key"),
            2 => String::from("Development-fused Key"),
            x => format!("Unknown Selector ({x:x})")
        });
        let ksize = (keyhead.key_size/8) as usize;
        println!("\tKey size: AES{}", ksize*8);
        println!("\tIV: {iv}", iv=hex::encode(keyhead.iv_bytes));
        println!("\tKey: {key}", key=hex::encode(&keyhead.key_bytes[..ksize]));
    } else if let Some(kbg) = &args.setkbag {
        assert_eq!(kbg.len(), 3);
        assert!(
            kbg[0].len() == 32, 
            "IV is not 32 hex characters in length, instead got {}", 
            kbg[0].len()
        );
        assert!(
            kbg[1].len() == (&keyhead.key_size/4) as usize, 
            "Key does not match keybag size to be replaced, expected {} but got {}", 
            keyhead.key_size/8, 
            kbg[1].len()
        );
        let sel = match kbg[2].as_ref() { 
            "prod" => 1, 
            "dev" => 2, 
            _ => panic!("Invalid type selected") 
        };
        if keyhead.selector == sel {
            let mut iv_bytes = hex::decode(kbg[0].as_bytes()).unwrap();
            if iv_bytes.len() < 16 {
                let need = 16 - iv_bytes.len() + 1;
                iv_bytes.resize(need, 0);
            }
            let mut key_bytes = hex::decode(kbg[1].as_bytes()).unwrap();
            if key_bytes.len() != (&keyhead.key_size/8) as usize {
                let need = (&keyhead.key_size/8) as usize - key_bytes.len() + 1;
                key_bytes.resize(need, 0);
            }
            keyhead.iv_bytes = (&iv_bytes[..]).try_into().unwrap();
            keyhead.key_bytes = (&key_bytes[..]).try_into().unwrap();
            struct_write!(keyhead, taghead.buf);
            struct_write!(taghead, file[i..]);
            
            if !args.onlykbag {
                //need to encrypt DATA with the keybag
                let mut datahead = cast_struct!(IMG3TagHeader, &file[data..]);
                let padded = [datahead.buf, datahead.pad.clone()].concat();
                
                let cipher = match kbg[1].len() {
                    32 => Cipher::aes_128_cbc(),
                    48 => Cipher::aes_192_cbc(),
                    64 => Cipher::aes_256_cbc(),
                    x => panic!("Invalid key size: {x}")
                };

                let mut encrypter = Crypter::new(
                    cipher,
                    Mode::Encrypt,
                    &key_bytes,
                    Some(&iv_bytes)
                ).unwrap();
                encrypter.pad(false);
                let mut buf = vec![0; padded.len() + cipher.block_size()];
                let count = encrypter.update(
                    &padded, 
                    &mut buf
                ).unwrap();
                encrypter.finalize(&mut buf).unwrap();
                buf.truncate(count);
                datahead.buf = buf;
                struct_write!(datahead, file[data..]);
            }
        }
    } else if args.dec {
        //remove keybag headers
        file.drain(range_size(i, taghead.skip_dist as usize));
        mainhead.buf_len -= taghead.skip_dist;
        mainhead.skip_dist -= taghead.skip_dist;
        struct_write!(mainhead, file[0..]);
        return true;
    };
    false
}

fn new_kbag(sects: &mut Vec<IMG3TagHeader>, args: &Args) {
    if let Some(kbg) = &args.setkbag {
        let mut tagbuf = Vec::new();
        
        assert_eq!(kbg.len(), 3);
        assert!(kbg[0].len() == 32, "IV is not 32 hex characters in length, instead got {}", kbg[0].len());
        let mut iv_bytes = hex::decode(&kbg[0]).unwrap();
        if iv_bytes.len() < 16 {
            let need = 16 - iv_bytes.len() + 1;
            iv_bytes.resize(need, 0);
        }
        let mut key_bytes = hex::decode(&kbg[1]).unwrap();
        if key_bytes.len() != kbg[0].len() {
            let need = kbg[0].len() - key_bytes.len() + 1;
            key_bytes.resize(need, 0);
        }

        let keyhead = IMG3KBAG {
            selector: match kbg[3].as_str() {
                "prod" => 1,
                "dev" => 2,
                _ => 0
            },
            key_size: cast_force!(key_bytes.len(), u32),
            iv_bytes: cast_force!(iv_bytes.clone(), [u8; 0x10]),
            key_bytes: cast_force!(key_bytes.clone(), [u8; 0x20])
        };
        struct_write!(keyhead, tagbuf);
        let buflen = tagbuf.len();
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_KEYBAG,
            skip_dist: 12 + cast_force!(buflen + buflen % 4, u32),
            buf_len: cast_force!(buflen, u32),
            buf: tagbuf,
            pad: vec![0; buflen % 4],
        });

        if !args.onlykbag {
            //need to encrypt DATA with the keybag
            let (off, dh) = sects.iter().enumerate().find(|x| x.1.tag == IMG3_GAT_DATA).unwrap();
            let mut datahead = dh.clone();
            let padded = [datahead.buf, datahead.pad.clone()].concat();
            
            let cipher = match kbg[1].len() {
                32 => Cipher::aes_128_cbc(),
                48 => Cipher::aes_192_cbc(),
                64 => Cipher::aes_256_cbc(),
                x => panic!("Invalid key size: {x}")
            };

            let buf = encrypt(
                cipher, 
                &key_bytes, 
                Some(&iv_bytes),
                &padded
            ).unwrap_or_else(|e| 
                panic!("{} to encrypt img3 DATA section, error: {e}", "Failed".red())
            );

            datahead.buf = buf;
            sects[off] = datahead;
        }
    }
}

/// # Panics
/// Panics if the arguments are incorrect.
pub fn create(mut buf: Vec<u8>, args: &Args) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = IMG3ObjHeader {
        magic: IMG3_HEADER_CIGAM,
        ..Default::default()
    };

    let mut sects: Vec<IMG3TagHeader> = Vec::new();

    if let Some(settype) = &args.settype {
        assert!(settype.len() == 4, "Tag is not length 4");
        objh.img3_type = u32::from_be_bytes(cast_force!(settype.as_bytes(), [u8; 4]));
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_TYPE,
            skip_dist: 0x20,
            buf_len: 4,
            buf: settype.chars().rev().collect::<String>().as_bytes().to_vec(),
            pad: vec![0; 0x10],
        });
    }

    if args.comp {
        let lzsscomp = compress(&buf);
        let compsz = lzsscomp.len();
        let lzsshead = create_complzss_header(&buf, lzsscomp);
        struct_write!(lzsshead, buf);
        buf.truncate(384 + compsz);
    }
    let datlen = buf.len();
    sects.push(IMG3TagHeader {
        tag: IMG3_GAT_DATA,
        skip_dist: 12 + cast_force!(datlen + datlen % 4, u32),
        buf_len: cast_force!(datlen, u32),
        buf,
        pad: vec![0; datlen % 4]
    });

    if let Some(vers) = &args.setver {
        let mut tagbuf = Vec::new();
        let tagstr = IMG3TagString {
            str_bytes: vers.clone(),
            str_len: cast_force!(vers.len(), u32),
        };
        struct_write!(tagstr, tagbuf);
        let buflen = tagbuf.len();
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_VERSION,
            skip_dist: 12 + cast_force!(buflen + buflen % 4, u32) ,
            buf_len: cast_force!(buflen, u32),
            buf: tagbuf,
            pad: vec![0; buflen % 4],
        });
    }
    
    new_kbag(&mut sects, args);

    if let Some(sigpath) = &args.sigpath {
        let sig = fs::read(sigpath).unwrap();
        let siglen = sig.len();
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_SIGNED_HASH,
            skip_dist: 12 + cast_force!(siglen + siglen % 4, u32),
            buf_len: cast_force!(siglen, u32),
            buf: sig,
            pad: vec![0; siglen % 4],
        });
    }
    if let Some(certpath) = &args.certpath {
        let cert = fs::read(certpath).unwrap();
        let certlen = cert.len();
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_CERTIFICATE_CHAIN,
            skip_dist: 12 + cast_force!(certlen + certlen % 4, u32),
            buf_len: cast_force!(certlen, u32),
            buf: cert,
            pad: vec![0; certlen % 4],
        });
    }

    let count: u32 = sects.iter().map(|x| x.skip_dist).sum();
    objh.skip_dist = 20 + count;
    objh.buf_len = count;
    let signed: u32 = sects
        .iter()
        .filter_map(|x| (![IMG3_GAT_SIGNED_HASH, IMG3_GAT_CERTIFICATE_CHAIN].contains(&x.tag)).then_some(x.skip_dist))
        .sum();
    objh.signed_len = signed;
    struct_write!(objh, newimg);
    for i in sects {
        let mut v = Vec::new();
        struct_write!(i, v);
        newimg.extend_from_slice(&v);
    }
    write_file(args.outfile.as_ref().unwrap(), &newimg);
}

fn parse_blob(args: &Args, 
              head: &mut IMG3ObjHeader, 
              is_ext: bool, 
              apticket: &mut Option<Vec<u8>>,
              ecid_size: u32, 
              file: &mut Vec<u8>) {
    if let Some(shshpath) = &args.shshpath {
        if !is_ext {
            let imgtype = match head.img3_type {
                IMG3_TAG_CHG0 => "BatteryCharging0",
                IMG3_TAG_CHG1 => "BatteryCharging1",
                IMG3_TAG_BATF => "BatteryFull",
                IMG3_TAG_BAT0 => "BatteryLow0",
                IMG3_TAG_BAT1 => "BatteryLow1",
                IMG3_TAG_DTRE => "DeviceTree",
                IMG3_TAG_DIAG => "Diags",
                IMG3_TAG_GLYC => "BatteryCharging",
                IMG3_TAG_GLYP => "BatteryPlugin",
                IMG3_TAG_IBEC => "iBEC",
                IMG3_TAG_IBOT => "iBoot",
                IMG3_TAG_IBSS => "iBSS",
                IMG3_TAG_ILLB => "LLB",
                IMG3_TAG_KRNL => "KernelCache",
                IMG3_TAG_LOGO => "AppleLogo",
                IMG3_TAG_RDSK => "RestoreRamDisk",
                IMG3_TAG_RDTR => "RestoreDeviceTree",
                IMG3_TAG_RECM => "RecoveryMode",
                IMG3_TAG_RKRN => "RestoreKernelCache",
                IMG3_TAG_RLGO => "RestoreLogo",
                _ => panic!("Unknown image type to be stitched")
            };
            let mut shshfile = fs::File::open(shshpath).expect("Failed to read blob");
            let mut buf = vec![0; 5];
            shshfile.read_exact(&mut buf).expect("Failed to read blob");

            if buf[..2] == [0x30, 0x82] { // raw APTicket
                *apticket = Some(fs::read(shshpath).expect("Failed to read APTicket"));
            } else {
                let mut part_dgst = vec![];
                let blob;
                if buf == *b"<?xml" { // SHSH blob
                    let fullblob = Value::from_file(shshpath).expect("Failed to read blob");
                    *apticket = fullblob.as_dictionary()
                               .and_then(|dict| dict.get("APTicket")?.as_data())
                               .map(<[u8]>::to_vec);

                    if let Some(imgblob) = fullblob.as_dictionary().and_then(|dict| dict.get(imgtype)?.as_dictionary()) {
                        part_dgst = imgblob.get("PartialDigest")
                                    .and_then(|pdigest| pdigest.as_data())
                                    .expect("Did not find the required PartialDigest (personalization not required?)")
                                    .to_vec();
                        assert!(part_dgst.len() > 8, "Partial Digest too small!");

                        blob = imgblob.get("Blob")
                               .and_then(|blob| blob.as_data())
                               .expect("Did not find the required blob (personalization not required?)")
                               .to_vec();
                        let oldsign = head.signed_len - ecid_size; // should be &part_dgst[4..8] as u32
                        head.signed_len += u32::from_le_bytes(cast_force!(&part_dgst[0..4], [u8; 4]));
                        head.buf_len = oldsign + cast_force!(blob.len(), u32);
                        head.skip_dist = oldsign + cast_force!(blob.len(), u32) + /* sizeof IMG3ObjHeader */ 0x14;
                        file.splice(/* sizeof IMG3ObjHeader */ 0x14 + oldsign as usize.., blob);
                        struct_write!(head, file[0..]);
                    }
                } else { //raw blob
                    blob = fs::read(shshpath).expect("Failed to read blob");
                    let oldsign = head.signed_len - ecid_size; // should be &part_dgst[4..8] as u32
                    head.signed_len += u32::from_le_bytes(cast_force!(&part_dgst[0..4], [u8; 4]));
                    head.buf_len = oldsign + cast_force!(blob.len(), u32);
                    head.skip_dist = oldsign + cast_force!(blob.len(), u32) + /* sizeof IMG3ObjHeader */ 0x14;
                    file.splice(/* sizeof IMG3ObjHeader */ 0x14 + oldsign as usize.., blob);
                    struct_write!(head, file[0..]);
                };
            }
        }
    } else if let Some(argapticket) = &args.apticketbuf {
        *apticket = Some(argapticket.clone());
    }
}

/// # Panics
/// Panics if the buffer does not contain a valid IMG3 file, or the arguments are incorrect.
#[expect(clippy::too_many_lines, clippy::cognitive_complexity)] // refactor required
pub fn parse(mut file: Vec<u8>, args: &mut Args, is_valid: &mut bool, devinfo: &mut Option<DeviceInfo>) -> Option<Vec<u8>> {
    let mut head = cast_struct!(IMG3ObjHeader, &file);
    let is_ext = head.img3_type == IMG3_TAG_CERT;
    let mut apticket = None;
    let ecid_size = if !is_ext && 
                    (0x14 + head.signed_len as usize).checked_sub(0x40).is_some() && 
                    (file[range_size(0x14 + head.signed_len as usize - 0x40, 4)] == IMG3_GAT_UNIQUE_ID ||
                    file[range_size(0x14 + head.signed_len as usize - 0x40, 4)] == IMG3_GAT_RANDOM) // Haywire specific (?)
                    { 0x40 } else { 0 };
    // TODO: remove ECID tag entirely
    if ecid_size != 0 {
        head.signed_len -= ecid_size;
        struct_write!(head, file);
    }
    let sha1 = if head.signed_len != 0 { sha1(&file[range_size(0xC, 0x8 + head.signed_len as usize)]) } else { [0;20] };
    let partialsha1 = if head.signed_len != 0 { crate::apticket::partial_sha1(&file[range_size(0xC, 0x8 + head.signed_len as usize)]).unwrap() } else { Vec::new() };
    if ecid_size != 0 {
        head.signed_len += ecid_size;
        struct_write!(head, file);
    }
    let mut vers = None;
    if args.all {
        println!("{head}");
    }
    if let Some(fourcc) = &args.settype {
        assert!(fourcc.len() == 4, "Tag is not 4 bytes");
        head.img3_type = u32::from_be_bytes(fourcc.as_bytes().try_into().unwrap());
        struct_write!(head, file);
    }
    
    let cached_res = args.apticketbuf.is_some();
    parse_blob(args, &mut head, is_ext, &mut apticket, ecid_size, &mut file);

    let mut i = 20;
    let mut data: usize = 0x34;
    let mut shshdata = Vec::new();
    let mut sawcert = false;
    while i < 20 + head.buf_len as usize { //tag parse loop until EOF
        let mut taghead = cast_struct!(IMG3TagHeader, &file[i..]);
        let tag = revstr_from_le_bytes(&taghead.tag);
        if args.all {
            println!("{taghead}");
        }
        match tag.as_str() {
            IMG3_TAG_VERSION => {
                let mut vershead = cast_struct!(IMG3TagString, &taghead.buf);
                vers = Some(vershead.str_bytes.clone());
                if args.all || args.ver {
                    println!("{}Version string: {vers}", if args.all {"\t"} else {""}, vers=vershead.str_bytes);
                } else if let Some(vers) = &args.setver {
                    println!("Version was: {oldv}", oldv=vershead.str_bytes);
                    vershead.str_bytes.clone_from(vers);
                    vershead.str_len = cast_force!(vershead.str_bytes.len(), u32);
                    struct_write!(vershead, taghead.buf);
                    let buf = taghead.buf.clone();
                    do_resize(&mut head, &mut taghead, &mut file, i, vershead.str_len + 4, buf);
                    println!("Version is: {vers}", vers=vershead.str_bytes);
                }
            }, IMG3_TAG_TYPE => {
                if args.all || args.imgtype {
                    println!("{}Type: {}", if args.all {"\t"} else {""}, revstr_from_le_bytes(&taghead.buf));
                } else if let Some(fourcc) = &args.settype {
                    println!("Type was: {tag}", tag=revstr_from_le_bytes(&taghead.buf));
                    fourcc.chars().rev().enumerate().for_each(|(index, c)| {
                        taghead.buf[index] = c as u8;
                    });
                    struct_write!(head, file);
                    struct_write!(taghead, file[i..]);
                    println!("Type is: {fourcc}");
                }
            }, IMG3_TAG_OVERRIDE => {
                let ov = u32::from_le_bytes(taghead.buf.try_into().unwrap());
                println!("\tOverride: {} ({ov:#X})", override_types(ov));
                if let Some(ref mut info) = devinfo {
                    info.ovrd = Some(ov);
                } else {
                    *devinfo = Some(DeviceInfo { ovrd: Some(ov), ..Default::default() });
                }
            }, IMG3_TAG_KEYBAG => {
                if kbag_tag(args, &mut head, &mut taghead, &mut file, i, data) { continue; }
            }, IMG3_TAG_CERTIFICATE_CHAIN => {
                sawcert = true;
                if let Some(ref apticket) = apticket {
                    let is_ok = if cached_res { cached_res } else { apticket::validate(apticket) };
                    if is_ok {
                        let (_, nonce) = apticket::parse(apticket, head.img3_type, &sha1, &partialsha1, vers.as_deref(), is_valid);
                        if head.img3_type != IMG3_TAG_IBSS && head.img3_type != IMG3_TAG_ILLB { // only these 2 don't require nonce
                            if let Some(ref mut devinfo) = devinfo {
                                devinfo.nonc = nonce;
                            } else {
                                *devinfo = Some(DeviceInfo { nonc: nonce, ..Default::default() });
                            }
                        }
                    } else {
                        println!("Not parsing invalid APTicket.");
                    }
                }
                if let Some(path) = &args.savecertpath {
                    write_file(path, &taghead.buf);
                } else if let Some(certpath) = &args.certpath {
                    let certfile = fs::read(certpath).unwrap();
                    let taglen = 12 + cast_force!(taghead.buf.len() + taghead.pad.len(), u32);
                    do_resize(&mut head, &mut taghead, &mut file, i, taglen, certfile);
                }
                if cert_tag(args, &head, &taghead, &file, &shshdata, is_valid, devinfo) { break; }
            }, IMG3_TAG_UNIQUE_ID => { //number, but this has a uint64 size
                if args.all || args.verify {
                    let cur_ecid = u64::from_le_bytes(taghead.buf.try_into().unwrap());
                    if args.all {
                        println!("\tECID: \n\t\tDec: {cur_ecid}, \n\t\tHex: {cur_ecid:X}");
                    }
                    if let Some(ref mut devinfo) = devinfo {
                        devinfo.ecid = Some(cur_ecid);
                    } else {
                        *devinfo = Some(DeviceInfo { ecid: Some(cur_ecid), ..Default::default() });
                    }
                }
            }, IMG3_TAG_SECURITY_DOMAIN => {
                let sdom = u32::from_le_bytes(taghead.buf.try_into().unwrap());
                if args.all {
                    println!("\tSecurity Domain: {}", match sdom {
                                x@0 => format!("{x:#x} (Manufacturer)"),
                                x@1 => format!("{x:#x} (Darwin)"),
                                x@3 => format!("{x:#x} (RTXC)"),
                                x => format!("Unknown Security Domain ({x})")
                    });
                }
                if is_ext { // SDOM can only be checked from certificate extension
                    if let Some(ref mut devinfo) = devinfo {
                        devinfo.sdom = Some(sdom);
                    } else {
                        *devinfo = Some(DeviceInfo { sdom: Some(sdom), ..Default::default() });
                    }
                }
            }, IMG3_TAG_DATA => {
                data = i;
                data_tag(args, &mut head, &mut taghead, &mut file, i);
            }, IMG3_TAG_SIGNED_HASH => {
                if let Some(path) = &args.savesigpath {
                    write_file(path, &taghead.buf);
                } else if let Some(sigpath) = &args.sigpath {
                    let hashfile = fs::read(sigpath).unwrap();
                    let taglen = 12 + cast_force!(taghead.buf.len() + taghead.pad.len(), u32);
                    do_resize(&mut head, &mut taghead, &mut file, i, taglen, hashfile);
                }
                shshdata = taghead.buf;
            }, x @ (IMG3_TAG_SECURITY_EPOCH |
               IMG3_TAG_PRODUCTION_STATUS   |
               IMG3_TAG_CHIP_TYPE           |
               IMG3_TAG_BOARD_TYPE          |
               IMG3_TAG_HARDWARE_EPOCH) => {
                print_unknown_val(args, &taghead);
                let val = u32::from_le_bytes(taghead.buf.try_into().unwrap());

                //helper macro for adding in device info
                macro_rules! add_device_info {
                    ($field_name: ident, $nested: ident) => {
                        if ($nested && is_ext) || (!$nested) {
                            if let Some(ref mut info) = devinfo {
                                info.$field_name = Some(val);
                            } else {
                                *devinfo = Some(DeviceInfo { $field_name: Some(val), ..Default::default() });
                            }
                        }
                    }
                }
                
                match x {
                    IMG3_TAG_SECURITY_EPOCH    => add_device_info!(sepo, false), 
                    IMG3_TAG_PRODUCTION_STATUS => add_device_info!(prod, true), 
                    IMG3_TAG_CHIP_TYPE         => add_device_info!(cpid, true), 
                    IMG3_TAG_HARDWARE_EPOCH    => add_device_info!(cepo, true), 
                    IMG3_TAG_BOARD_TYPE        => {
                        if let Some(ref mut devinfo) = devinfo {
                            if let Some(ref mut bdid) = devinfo.bdid {
                                bdid.push(val);
                            } else {
                                devinfo.bdid = Some(vec![val]);
                            }
                        } else {
                            *devinfo = Some(DeviceInfo { bdid: Some(vec![val]), ..Default::default() });
                        }
                    }, _ => { unreachable!("This match should be unreachable") }
                }
            }, 
            IMG3_TAG_RANDOM_PAD => {}, // ignore padding
            IMG3_TAG_NONCE => {
                print_unknown_val(args, &taghead);
                let val: [u8; 20] = taghead.buf.try_into().unwrap();
                if let Some(ref mut info) = devinfo {
                    info.nonc = Some(val);
                } else {
                    *devinfo = Some(DeviceInfo { nonc: Some(val), ..Default::default() });
                }
            }, IMG3_TAG_RANDOM => {
                print_unknown_val(args, &taghead);
            }, x => { // assume number
                print_unknown_val(args, &taghead);
                eprintln!("Unknown tag found (\"{x}\"), please file a issue!");
            }
        }
        i += taghead.skip_dist as usize;
    }

    if let Some(path) = &args.outfile {
        // setter args create a img3
        if args.setver.is_some() || 
           args.setkbag.is_some() ||
           args.settype.is_some() || 
           args.setdata.is_some() || 
           args.sigpath.is_some() || 
           args.certpath.is_some() || 
           args.shshpath.is_some() {
            write_file(path, &file);
        }
    }

    if !sawcert && args.verify {
        if head.img3_type == IMG3_TAG_SCAB {
            let data = cast_struct!(IMG3TagHeader, &file[data..]);
            return Some(data.buf);
        }
        if let Some(ref apticket) = apticket {
            let is_ok = if cached_res { cached_res } else { apticket::validate(apticket) };
            if is_ok {
                let (mut devinfo, nonce) = apticket::parse(apticket, head.img3_type, &sha1, &partialsha1, vers.as_deref(), is_valid);
                println!("This image is {} by APTicket{}", 
                        if *is_valid {
                            "validated".green()
                        } else {
                            "invalidated".red()
                        },
                        if *is_valid { // no point showing the info if it's invalid anyways
                            devinfo.nonc = nonce;
                            Cow::from(devinfo.to_string())
                        } else {
                            Cow::from("")
                        }
                );
            } else {
                println!("Not parsing invalid APTicket.");
            }
        } else {
            println!("File cannot be verified without either a CERT and SHSH tag, or an APTicket.");
        }
    }

    None
}