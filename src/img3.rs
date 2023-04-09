use {
    crate::{
        Args, 
        utils::*
    },
    std::{
        fs, 
        process::exit
    },
    binrw::BinReaderExt,
    colored::Colorize,
    openssl::{
        symm::{
            Cipher, 
            Crypter, 
            Mode, 
            encrypt
        },
        rsa::Padding,
        sign::Verifier,
        hash::MessageDigest
    },
    plist::Value
};

fn cert_tag(args: &mut Args, head: &mut IMG3ObjHeader, taghead: &mut IMG3TagHeader, file: &mut Vec<u8>, i: usize, shshdata: &[u8], is_valid: &mut bool, devinfo: &mut Option<DeviceInfo>) -> bool {
    if let Some(path) = &args.savecertpath {
        write_file(path, &taghead.buf);
    } else if let Some(certpath) = &args.certpath {
        let certfile = fs::read(certpath).unwrap();
        let taglen = 12 + cast_force!(taghead.buf.len() + taghead.pad.len(), u32);
        do_resize(head, taghead, file, i, taglen, certfile);
    }

    if args.verify {
        let mut i = 0;
        let check = u16::from_be_bytes(taghead.buf[range_size(i, 2)].try_into().unwrap());
        if check == 0x3082 {
            let mut deridx = 0;
            let mut certs: Vec<X509> = Vec::new();
            while i < taghead.buf.len() {
                /* the following does not work (extra data error)
                let parse_cert: asn1::ParseResult<_> = asn1::parse(&taghead.buf[i..i+len], |d| {
                    let tlv = d.read_element::<asn1::Tlv>()?;
                    let data = asn1::parse(tlv.data(), |d| {
                        return Ok(d.read_element::<asn1::Tlv>()?.data())
                    })?;
                    return Ok((tlv.full_data().len(), data))
                });
                */
                let check = u16::from_be_bytes(taghead.buf[range_size(i, 2)].try_into().unwrap());
                assert_eq!(check, 0x3082);
                deridx = i;
                let len = u16::from_be_bytes(taghead.buf[range_size(i + 2, 2)].try_into().unwrap()) as usize;
                certs.push(X509::from_der(&taghead.buf[range_size(i, 4 + len)]).unwrap());
                i += 4 + len;
            }
        
            let mut certiter = certs.iter().enumerate();
            println!("Assuming \"{}\" is trusted", get_cn(certiter.next().unwrap().1));
        
            for (j, cert) in certiter {
                let cn = get_cn(cert);
                match cert.verify(&certs[j - 1].public_key().unwrap()) {
                    Ok(_) => println!("\"{cn}\" is {}", "valid".green()),
                    Err(e) => {
                        *is_valid = false;
                        println!("{} verification of {cn} with error: {e}", "Failed".red());
                    },
                }
            }
        
            let leafcert = &certs[certs.len()-1];

            unsafe {
                /* 
                * openssl crate does not implement the below functions, 
                * use unsafe to call the openssl_sys versions ourselves and check for errors 
                */
                use openssl_sys::{
                    OBJ_create, NID_undef,
                    d2i_X509, X509_free, X509_get_ext_by_NID, X509_get_ext, 
                    X509_EXTENSION_get_data,
                    ASN1_STRING, ASN1_STRING_length, ASN1_STRING_get0_data
                };
                use std::{
                    ffi::CString,
                    ptr::{null_mut, addr_of_mut},
                    slice::from_raw_parts
                };

                let mut x509_loc_ptr = taghead.buf[deridx..].as_ptr();
                let unsafe_x509_cert = d2i_X509(null_mut(), addr_of_mut!(x509_loc_ptr), taghead.buf[deridx..].len() as i64);
                assert!(!unsafe_x509_cert.is_null(), "Failed to parse X509");

                //CFTypeRef kSecOIDAPPLE_EXTENSION_APPLE_SIGNING = CFSTR("1.2.840.113635.100.6.1.1");
                let as_obj_id = CString::new("1.2.840.113635.100.6.1.1").unwrap();
                let as_short  = CString::new("APPLE_SIGNING").unwrap();
                let as_long   = CString::new("APPLE_EXTENSION_APPLE_SIGNING").unwrap();
                let as_nid    = OBJ_create(as_obj_id.as_ptr(), as_short.as_ptr(), as_long.as_ptr());
                assert!(as_nid != NID_undef, "Failed to create NID");

                let nid_idx = X509_get_ext_by_NID(unsafe_x509_cert, as_nid, -1);
                if nid_idx != -1 {
                    println!("Found Apple certificate signing extension, parsing it");
                    let ext     = X509_get_ext(unsafe_x509_cert, nid_idx);
                    assert!(!ext.is_null(), "Failed to get extension");
                    
                    let val     = X509_EXTENSION_get_data(ext) as *const ASN1_STRING; // infallable according to docs
                    let len     = ASN1_STRING_length(val);    // infallable according to docs
                    let dataptr = ASN1_STRING_get0_data(val); // infallable according to docs
                    let asn1_slice = from_raw_parts(dataptr, len.try_into().unwrap());
                    let img3_slice = asn1::parse_single::<&[u8]>(asn1_slice).unwrap();

                    assert_eq!(img3_slice[0..4], IMG3_HEADER_CIGAM, "Apple certificate signing extension does not contain IMG3 data");
                    parse(img3_slice.to_vec(), args, is_valid, devinfo); // skip 2 bytes because those encode the length
                }
                X509_free(unsafe_x509_cert);
            } //end unsafe

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
            println!("This image is {}{}", 
                    if *is_valid {
                        "valid".green()
                    } else {
                        "invalid".red()
                    },
                    if let Some(devinfo) = devinfo {
                        let mut s = if let Some(ecid) = devinfo.ecid {
                            vec![format!(" for the device with following:\n\tECID with hex: {ecid:X}")]
                        } else {
                            vec![String::from(", but unpersonalized with the following constraints:")]
                        };
                        if let Some(board) = &devinfo.bdid {
                            s.push(format!("\tBoard ID{}: {board}", 
                                if board.len() > 1 {"s"} else {""},
                                board=board.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
                            ));
                        }   
                        if let Some(chip) = &devinfo.cpid {
                            s.push(format!("\tChip ID: 0x{chip:X}"));
                        }
                        if let Some(sdom) = &devinfo.sdom {
                            s.push(format!("\tSecurity Domain: 0x{sdom:X} ({})",
                            match sdom {
                                0 => Cow::from("Manufacturer"),
                                1 => Cow::from("Darwin"),
                                3 => Cow::from("RTXC"),
                                x => Cow::from(format!("Unknown Security Domain ({x})"))
                            }));
                        }
                        if let Some(sepo) = &devinfo.sepo {
                            s.push(format!("\tSecurity Epoch: 0x{sepo:X}"));
                        }
                        if let Some(cepo) = &devinfo.cepo {
                            s.push(format!("\tHardware Epoch: 0x{cepo:X}"));
                        }
                        if let Some(prod) = &devinfo.prod {
                            s.push(format!("\tProduction Mode: {}", match prod {
                                0 => "No",
                                1 => "Yes",
                                _ => "Unknown"
                            }));
                        }
                        
                        s.join("\n")
                    } else {
                        String::from("(but not personalized)")
                    }
            );
            return true;
        }
        println!("Found a CERT tag with invalid data, skipping verification");
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

    if let (Some(key), Some(path)) = (&args.key, &args.outfile) {  
        let padded = [taghead.buf.clone(), taghead.pad.clone()].concat(); //this might not be necessary
        let mut key = key.clone();
        let iv: String = args.iv.clone().unwrap_or_else(|| {
            let ret = key[..32].to_string();
            key = key[32..].to_string();
            ret
        });
        let key_bytes: &[u8] = &hex::decode(key.as_bytes()).unwrap();
        let iv_bytes:  &[u8] = &hex::decode(iv.as_bytes()).unwrap();
        
        let cipher = match key.len() {
            32 => Cipher::aes_128_cbc(),
            48 => Cipher::aes_192_cbc(),
            64 => Cipher::aes_256_cbc(),
            x => panic!("Invalid key size: {x}")
        };

        let mut decrypter = Crypter::new(
            cipher,
            Mode::Decrypt,
            key_bytes,
            Some(iv_bytes)
        ).unwrap();
        decrypter.pad(false);
        let mut buf = vec![0; padded.len() + cipher.block_size()];
        let count = decrypter.update(
            &padded, 
            &mut buf
        ).unwrap();
        decrypter.finalize(&mut buf).unwrap_or_else(|e| {
            use std::io::Write;
            println!("Got a error whilst finalizing the decryption: \"{e}\"");
            print!("This can sometimes still contain valid data, continue? [y/N]: ");
            std::io::stdout().flush().unwrap();
            let mut opt = String::new();
            std::io::stdin().read_line(&mut opt).unwrap();
            if opt.trim() == "y" { 
                 0
            } else {
                std::process::exit(1);
            }
        });
        buf.truncate(count);
        
        if args.dec {
            taghead.buf = buf.clone();
            struct_write!(taghead, file[i..]);
        } else {
            write_file(path, &checkvalid_decry(&buf, head.img3_type, args.ext).unwrap_or(buf));
            exit(0);
        }
    } else if let Some(path) = &args.outfile {
        // if img3 setters are used, it wouldn't make sense to output the data buffer
        if args.setdata.is_none() 
        && args.setver.is_none() 
        && args.setkbag.is_none() 
        && args.settype.is_none()
        && args.setdata.is_none()
        && args.sigpath.is_none()
        && args.certpath.is_none()
        && args.shshpath.is_none() {
            write_file(path, &checkvalid_decry(&taghead.buf, head.img3_type, args.ext).unwrap_or(taghead.buf.clone()));
            exit(0);
        }
    }
}

fn kbag_tag(args: &Args, mainhead: &mut IMG3ObjHeader, taghead: &mut IMG3TagHeader, file: &mut Vec<u8>, i: usize, data: usize) -> bool{
    let mut keyhead = cast_struct!(IMG3KBAG, &taghead.buf);
    if args.all {
        println!("\tKey type: {}", match keyhead.selector {
            0 => String::from("Unencrypted Key"),
            1 => String::from("Production-fused Key"),
            2 => String::from("Development-fused Key"),
            x => format!("Unknown Selector ({x:x})")
        });
        let ksize = (&keyhead.key_size/8) as usize;
        println!("\tKey size: AES{}", ksize*8);
        println!("\tIV: {iv}", iv=hex::encode(keyhead.iv_bytes));
        println!("\tKey: {key}", key=hex::encode(&keyhead.key_bytes[..ksize]));
    } else if args.keybags {
        println!("Key type: {}", match keyhead.selector {
            0 => String::from("Unencrypted"),
            1 => String::from("Production"),
            2 => String::from("Development"),
            x => format!("Unknown ({x:x})")
        });
        println!("IV: {iv}", iv=hex::encode(keyhead.iv_bytes));
        println!("Key: {key}", key=hex::encode(&keyhead.key_bytes[..(&keyhead.key_size/8) as usize]));
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
                datahead.buf = buf.clone();
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

/// # Panics
/// Panics if the arguments are incorrect.
pub fn create(mut buf: Vec<u8>, args: &Args, outpath: &str) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = IMG3ObjHeader {
        magic: IMG3_HEADER_CIGAM,
        skip_dist: 0,
        buf_len: 0,
        signed_len: 0,
        img3_type: 0,
    };

    let mut sects: Vec<IMG3TagHeader> = Vec::new();

    if let Some(settype) = &args.settype {
        assert!(settype.len() == 4, "Tag is not length 4");
        objh.img3_type = u32::from_be_bytes(settype.as_bytes().try_into().unwrap());
        sects.push(IMG3TagHeader {
            tag: IMG3_GAT_TYPE,
            skip_dist: 0x20,
            buf_len: 4,
            buf: settype.chars().rev().collect::<String>().as_bytes().to_vec(),
            pad: vec![0; 16],
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
            iv_bytes: iv_bytes.clone().try_into().unwrap(),
            key_bytes: key_bytes.clone().try_into().unwrap()
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
            let (off, dh) = sects.iter().enumerate().find(|x| &x.1.tag == b"ATAD").unwrap();
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
    write_file(outpath, &newimg);
}

/// # Panics
/// Panics if the buffer does not contain a valid IMG3 file, or the arguments are incorrect.
pub fn parse(mut file: Vec<u8>, args: &mut Args, is_valid: &mut bool, devinfo: &mut Option<DeviceInfo>) {
    let mut head = cast_struct!(IMG3ObjHeader, &file);
    if args.all {
        println!("{head}");
    }
    if let Some(fourcc) = &args.settype {
        assert!(fourcc.len() == 4, "Tag is not 4 bytes");
        head.img3_type = u32::from_be_bytes(fourcc.as_bytes().try_into().unwrap());
        struct_write!(head, file);
    }
    if let Some(shshpath) = &args.shshpath {
        if head.img3_type != IMG3_TAG_CERT {
            let imgtype = match head.img3_type {
                IMG3_TAG_IBOT => "iBoot",
                IMG3_TAG_IBSS => "iBSS",
                IMG3_TAG_IBEC => "iBEC",
                IMG3_TAG_DTRE => "DeviceTree",
                IMG3_TAG_LOGO => "AppleLogo",
                IMG3_TAG_BAT0 => "BatteryLow0",
                IMG3_TAG_BAT1 => "BatteryLow1",
                IMG3_TAG_GLYC => "BatteryCharging",
                IMG3_TAG_CHG0 => "BatteryCharging0",
                IMG3_TAG_CHG1 => "BatteryCharging1",
                IMG3_TAG_GLYP => "BatteryPlugin",
                IMG3_TAG_BATF => "BatteryFull",
                IMG3_TAG_RECM => "RecoveryMode",
                IMG3_TAG_RKRN => "RestoreKernelCache",
                IMG3_TAG_RDTR => "RestoreDeviceTree",
                IMG3_TAG_RDSK => "RestoreRamDisk",
                IMG3_TAG_RLGO => "RestoreLogo",
                IMG3_TAG_ILLB => "LLB",
                IMG3_TAG_KRNL => "KernelCache",
                _ => panic!("Unknown image type to be stitched")
            };
            let fullblob = Value::from_file(shshpath).expect("Failed to read blob");
            let blob = fullblob.as_dictionary()
                               .and_then(|dict| dict.get(imgtype)?.as_dictionary())
                               .and_then(|imgblob| imgblob.get("Blob")?.as_data())
                               .expect("Did not find the required blob");
            let ecid = cast_struct!(IMG3TagHeader, blob);
            let ecidlen = ecid.skip_dist;
            file.splice(0x14+head.signed_len as usize.., blob.to_vec());
            let oldsign = head.signed_len;
            head.signed_len += ecidlen;
            head.buf_len = oldsign + blob.len() as u32;
            head.skip_dist = oldsign + blob.len() as u32 + 0x14;
            struct_write!(head, file[0..]);
        }
    }

    let mut i = 20;
    let mut data: usize = 0x34;
    let mut shshdata = Vec::new();
    while i < head.buf_len as usize { //tag parse loop until EOF
        let mut taghead = cast_struct!(IMG3TagHeader, &file[i..]);
        let tag = revstr_from_le_bytes(&taghead.tag);
        if args.all {
            println!("{taghead}");
        }
        match tag.as_str() {
            IMG3_TAG_VERSION => {
                let mut vershead = cast_struct!(IMG3TagString, &taghead.buf);
                if args.all || args.ver {
                    println!("{}Version string: {vers}", if args.all {"\t"} else {""}, vers=vershead.str_bytes);
                } else if let Some(vers) = &args.setver {
                    println!("Version was: {oldv}", oldv=vershead.str_bytes);
                    vershead.str_bytes = vers.clone();
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
                println!("\tOverride: {ov}");
            }, IMG3_TAG_KEYBAG => {
                if kbag_tag(args, &mut head, &mut taghead, &mut file, i, data) { continue; }
            }, IMG3_TAG_CERTIFICATE_CHAIN => {
                if cert_tag(args, &mut head, &mut taghead, &mut file, i, &shshdata, is_valid, devinfo) { break; }
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
                if let Some(ref mut devinfo) = devinfo {
                    devinfo.sdom = Some(sdom);
                } else {
                    *devinfo = Some(DeviceInfo { sdom: Some(sdom), ..Default::default() });
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
                    ($field_name: ident) => {
                        if let Some(ref mut info) = devinfo {
                            info.$field_name = Some(val);
                        } else {
                            *devinfo = Some(DeviceInfo { $field_name: Some(val), ..Default::default() });
                        }
                    }
                }
                
                match x {
                    IMG3_TAG_SECURITY_EPOCH    => add_device_info!(sepo), 
                    IMG3_TAG_PRODUCTION_STATUS => add_device_info!(prod), 
                    IMG3_TAG_CHIP_TYPE         => add_device_info!(cpid), 
                    IMG3_TAG_HARDWARE_EPOCH    => add_device_info!(cepo), 
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
            }, IMG3_TAG_RANDOM_PAD | IMG3_TAG_NONCE => {
                print_unknown_val(args, &taghead);
            }, _ => { // assume number
                print_unknown_val(args, &taghead);
                panic!("Unknown tag found, aborting");
            }
        }
        i += taghead.skip_dist as usize;
        //dbg!(taghead.tag, i);
        if i >= file.len() {
            break;
        }
    }
    if let Some(path) = &args.outfile {
        write_file(path, &file);
    }
}