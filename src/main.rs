//clippy config
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation, //forced to do this since it has to fit in the struct
    clippy::cast_lossless,            //same reason as above
    clippy::similar_names,            //'args' vs 'argc', lmk if anyone thinks up of better names
    clippy::if_not_else,              //block with more code on the top, also this is more clear
    clippy::struct_excessive_bools,   //arguments struct, can't change much
    clippy::wildcard_imports,         //too many imports to specify every one
    clippy::module_name_repetitions,  //lzss module, makes functions name more clear
    clippy::comparison_chain          //I don't want a exhaustive match, also it may be slower
)]

use clap::Parser;
use std::{
    fs, 
    process::exit, 
    env
};
//use byteorder::{BigEndian, ReadBytesExt};
use binrw::BinReaderExt;
use phf::phf_map; //static map because I know all the values
use colored::Colorize;

use crc32fast::hash;
use openssl::{
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
};

use memchr::memmem::find;

mod lzss;
mod utils;
use lzss::lzss_decode_block_content;
use utils::*;

#[derive(Parser, Debug, Clone)]
#[clap(author="@plzdonthaxme", version="1.0", about="A img2/3 parser, made in rust")]
struct Args {
    //main args
    #[clap(help="Input filename", value_name="INPUT")]
    filename: String,
    #[clap(help="Output filename", value_name="OUTPUT")]
    outfile: Option<String>,
    #[clap(short, help="Output all info about the image")]
    all: bool,
    #[clap(short='v', long, help="Verify the image")]
    verify: bool,
    #[clap(long, help="Specify iv for decryption")]
    iv: Option<String>,
    #[clap(short, long, help="Specify key for decryption", value_name="KEY|IVKEY")]
    key: Option<String>,
    #[clap(short='d', help="Only decrypt, do not extract (overrides -e)")]
    dec: bool,
    #[clap(short='2', help="(IMG2 only) Keep the IMG2 header, but remove the S5L header")]
    img2: bool,
    #[clap(short='e', help="Only extracts, do not decompress (only applies to kernel)")]
    ext: bool,

    //getters
    #[clap(long, help="Print version in IMG3", help_heading="GETTERS")]
    ver: bool,
    #[clap(short='b', help="Output keybags", help_heading="GETTERS")]
    keybags: bool,
    #[clap(short='t', help="Output image type", help_heading="GETTERS")]
    imgtype: bool,
    #[clap(short='s', help="Save the signature to a file", value_name="FILE", help_heading="GETTERS")]
    savesigpath: Option<String>,
    #[clap(short='c', help="Save the cert chain to a file", value_name="FILE", help_heading="GETTERS")]
    savecertpath: Option<String>,

    //setters
    #[clap(short='V', help="Set the version string in IMG3", value_name="VERSION", help_heading="SETTERS")]
    setver: Option<String>,
    #[clap(short='K', help="Set the keybag and encrypt data with it, type can be prod or dev", multiple_values = true, max_values = 3, value_names = &["IV", "KEY", "TYPE"], help_heading="SETTERS")]
    setkbag: Option<Vec<String>>,
    #[clap(short='B', help="Only set the keybag, do not encrypt", help_heading="SETTERS")]
    onlykbag: bool,
    #[clap(short='T', help="Set or rename the image type (4cc)", value_name="TYPE", help_heading="SETTERS")]
    settype: Option<String>,
    #[clap(short='D', help="Set or replace the data buffer from a file", value_name="TYPE", help_heading="SETTERS")]
    setdata: Option<String>,
    #[clap(short='S', help="Set or replace the signature from a file", value_name="FILE", help_heading="SETTERS")]
    sigpath: Option<String>,
    #[clap(short='C', help="Set or replace the cert chain from a file", value_name="FILE", help_heading="SETTERS")]
    certpath: Option<String>,

    //create
    #[clap(short='m', long, help="Create a image with a image type (setters will be used)", value_name="S5L|IMG3")]
    create: Option<String>,
}

fn format_type(value: u8) -> String {
    match value {
        1 => String::from("Boot encrypted with UID-key"),
        2 => String::from("Boot plaintext"),
        3 => String::from("Encrypted with Key 0x837"),
        4 => String::from("Plaintext"),
        _ => format!("Unknown Format ({value})")
    }
}

static OPTMAP: phf::Map<u32, &'static str> = phf_map! {
    0u32 => "External Signature",
    1u32 => "SHA1 in Signature Data",
    2u32 => "CRC32 in Signature Data",
    8u32 => "Trusted Image",
    9u32 => "Encrypted Image",
    24u32 => "Image with Secure Boot",
    30u32 => "With extension header",
    31u32 => "Immutable"
};

fn opts(val: u32) -> String {
    if val != 0 {
        OPTMAP
        .entries()
        .filter(|i| val & (1 << i.0) != 0)
        .map(|i| *i.1)
        .collect()
    } else {
        String::from("No Options")
    }
}

fn create_img3(buf: Vec<u8>, args: &Args, outpath: &str) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = IMG3ObjHeader {
        magic: *IMG3_HEADER_CIGAM,
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
            tag: *b"EPYT",
            skip_dist: 0x20,
            buf_len: 4,
            buf: settype.chars().rev().collect::<String>().as_bytes().to_vec(),
            pad: vec![0; 16],
        });
    }

    let datlen = buf.len();
    sects.push(IMG3TagHeader {
        tag: *b"ATAD",
        skip_dist: 12 + (datlen + datlen % 4) as u32,
        buf_len: datlen as u32,
        buf,
        pad: vec![0; datlen % 4]
    });

    if let Some(vers) = &args.setver {
        let mut tagbuf = Vec::new();
        let tagstr = IMG3TagString {
            str_bytes: vers.clone(),
            str_len: vers.len() as u32,
        };
        struct_write!(tagstr, tagbuf);
        let buflen = tagbuf.len();
        sects.push(IMG3TagHeader {
            tag: *b"SREV",
            skip_dist: 12 + (buflen + buflen % 4) as u32,
            buf_len: buflen as u32,
            buf: tagbuf,
            pad: vec![0; buflen % 4],
        });
    }
    if let Some(kbg) = &args.setkbag {
        let mut tagbuf = Vec::new();
        
        assert_eq!(kbg.len(), 3);
        assert!(kbg[0].len() == 32, "IV is not 32 hex characters in length, instead got {}", kbg[1].len());
        let mut iv_bytes = hex::decode(&kbg[0]).unwrap();
        if iv_bytes.len() < 16 {
            let need = 16 - iv_bytes.len() + 1;
            iv_bytes.resize(need, 0);
        }
        let mut key_bytes = hex::decode(&kbg[1]).unwrap();
        if key_bytes.len() != kbg[0].len() {
            let need = kbg[0].len() as usize - key_bytes.len() + 1;
            key_bytes.resize(need, 0);
        }

        let keyhead = IMG3KBAG {
            selector: match kbg[3].as_str() {
                "prod" => 1,
                "dev" => 2,
                _ => 0
            },
            key_size: key_bytes.len() as u32,
            iv_bytes: iv_bytes.clone().try_into().unwrap(),
            key_bytes: key_bytes.clone().try_into().unwrap()
        };
        struct_write!(keyhead, tagbuf);
        let buflen = tagbuf.len();
        sects.push(IMG3TagHeader {
            tag: *b"GABK",
            skip_dist: 12 + (buflen + buflen % 4) as u32,
            buf_len: buflen as u32,
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
                panic!("{} to encrypt img2 sha1, error: {e}", "Failed".red())
            );

            datahead.buf = buf;
            sects[off] = datahead;
        }
    }

    if let Some(sigpath) = &args.sigpath {
        let sig = fs::read(sigpath).unwrap();
        let siglen = sig.len();
        sects.push(IMG3TagHeader {
            tag: *b"HSHS",
            skip_dist: 12 + (siglen + siglen % 4) as u32,
            buf_len: siglen as u32,
            buf: sig,
            pad: vec![0; siglen % 4],
        });
    }
    if let Some(certpath) = &args.certpath {
        let cert = fs::read(certpath).unwrap();
        let certlen = cert.len();
        sects.push(IMG3TagHeader {
            tag: *b"TREC",
            skip_dist: 12 + (certlen + certlen % 4) as u32,
            buf_len: certlen as u32,
            buf: cert,
            pad: vec![0; certlen % 4],
        });
    }

    let count: u32 = sects.iter().map(|x| x.skip_dist).sum();
    objh.skip_dist = 20 + count;
    objh.buf_len = count;
    let signed: u32 = sects.iter().filter(|x| ![b"HSHS", b"TREC"].contains(&&x.tag)).map(|x| x.skip_dist).sum();
    objh.signed_len = signed;
    struct_write!(objh, newimg);
    for i in sects {
        let mut v = Vec::new();
        struct_write!(i, v);
        newimg.extend_from_slice(&v);
    }
    write_file(outpath, &newimg);
}

fn create_s5l(buf: &[u8], args: &Args, outpath: &str) {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = S5LHeader {
        platform: *b"8900",
        version: *b"1.0",
        format: 4,
        entry: 0,
        size_of_data: 0,
        footer_sig_off: 0,
        footer_cert_off: 0,
        footer_cert_len: 0,
        salt: [0; 0x20],
        unknown2: 0,
        epoch: 3,
        header_signature: [0; 0x10],
        _pad: [0; 0x7B0],
    };

    let (mut sig, mut cert) = (None, None);
    let img2 = &create_img2(buf, args);

    if let Some(sigpath) = &args.sigpath {
        sig = Some(fs::read(sigpath).unwrap());
        assert_eq!(sig.as_ref().unwrap().len(), 0x80);
        objh.footer_sig_off = img2.len() as u32;
    }

    if let Some(certpath) = &args.certpath {
        cert = Some(fs::read(certpath).unwrap());
        let certlen = cert.as_ref().unwrap().len();
        objh.footer_cert_off = objh.footer_sig_off + 0x80;
        objh.footer_cert_len = certlen as u32;
    }
    
    objh.size_of_data = img2.len() as u32;

    struct_write!(objh, newimg);
    newimg.extend_from_slice(img2);

    let mut sha1 = Sha1::new();
    sha1.update(&newimg[0..0x40]);
    let res = &sha1.finish()[0..0x10];
    let cipher = Cipher::aes_128_cbc();
    let encd = &encrypt(
        cipher, 
        b"\x18\x84\x58\xA6\xD1\x50\x34\xDF\xE3\x86\xF2\x3B\x61\xD4\x37\x74", 
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

fn create_img2(buf: &[u8], args: &Args) -> Vec<u8> {
    let mut newimg: Vec<u8> = Vec::new();
    let mut objh = IMG2Header {
        magic:           *b"2gmI",
        img_type:        [0; 4],
        revision:        0,
        sec_epoch:       3,
        load_addr:       0x1800_0000,
        data_size:       buf.len() as u32,
        decry_data_size: buf.len() as u32,
        alloc_size:      u32::MAX,
        opts:            0,
        sig_data:        [0; 0x10],
        extsize:         u32::MAX,
        header_crc32:    0,
    };

    if let Some(imgtype) = &args.settype {
        assert!(imgtype.len() == 4, "Type length is not 4");
        objh.img_type = imgtype.as_bytes().try_into().unwrap();
    }
    struct_write!(objh, newimg);
    objh.header_crc32 = hash(&newimg[0..0x64]);
    struct_write!(objh, newimg);
    newimg.extend_from_slice(&[0; 0x398]); //padding to 0x400
    newimg.extend_from_slice(buf);
    newimg
}

fn parse_s5l(file: &[u8], args: &Args) {
    let mut head = cast_struct!(S5LHeader, file);
    if args.all {
        println!("S5L Header:\
              \n\tPlatform: {},\
              \n\tVersion: {},\
              \n\tFormat: {},\
              \n\tEntry: {:#X},\
              \n\tSize of data: {:#X},\
              \n\tFooter signature offset: {:#X},\
              \n\tFooter certificate offset: {:#X},\
              \n\tFooter certificate length: {:#X},\
              \n\tSalt: {:02X?},\
              \n\tEpoch: {:#X},\
              \n\tHeader signature: {:02X?}", 
              from_utf8(&head.platform).unwrap(),
              from_utf8(&head.version).unwrap(),
              format_type(head.format),
              head.entry,
              head.size_of_data,
              head.footer_sig_off,
              head.footer_cert_off,
              head.footer_cert_len,
              head.salt,
              head.epoch,
              head.header_signature,
        );
    }
    
    let mut is_valid = true;
    if &head.platform == b"8900" {
        if let Some(path) = &args.savesigpath {
            write_file(path, &file[0x800 + head.footer_sig_off as usize..0x800 + head.footer_cert_off as usize]);
        }
        if let Some(path) = &args.savecertpath {
            write_file(path, &file[range_size(0x800 + head.footer_cert_off as usize, head.footer_cert_len as usize)]);
        }

        let cipher = Cipher::aes_128_cbc();
        if args.verify {
            let mut sha1 = Sha1::new();
            sha1.update(&file[0..0x40]);
            let res = &sha1.finish()[0..0x10];
            let encd = &encrypt(
                cipher, 
                b"\x18\x84\x58\xA6\xD1\x50\x34\xDF\xE3\x86\xF2\x3B\x61\xD4\x37\x74", 
                None,
                res
            ).unwrap_or_else(|e| 
                panic!("{} to encrypt img2 sha1, error: {e}", "Failed".red())
            )[0..0x10];

            is_valid = encd == head.header_signature;
            println!("Header signature is {}", 
                     if is_valid {
                         "correct".green()
                     } else {
                         "incorrect".red()
                     }
            );

            let mut i = head.footer_cert_off as usize + 0x800;
            let mut certs: Vec<X509> = Vec::new();
            while i < (head.footer_cert_off + 0x800 + head.footer_cert_len) as usize {
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

            let leafpub = certs[certs.len()-1].public_key().unwrap();
            let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
            verifier.set_rsa_padding(Padding::PKCS1).unwrap();
            verifier.update(&file[0..0x800 + head.footer_sig_off as usize]).unwrap();
            let ok = verifier.verify(&file[range_size(0x800 + head.footer_sig_off as usize, 0x80)]).unwrap();
            println!("8900 file signature is {}", 
                    if ok {
                        "valid".green()
                    } else {
                        is_valid = false;
                        "invalid".red()
                    }
            );
        }

        if head.format == 3 {
            let mut decrypter = Crypter::new(
                cipher,
                Mode::Decrypt,
                b"\x18\x84\x58\xA6\xD1\x50\x34\xDF\xE3\x86\xF2\x3B\x61\xD4\x37\x74",
                None
            ).unwrap();
            decrypter.pad(false);
            let mut decry = vec![0; head.footer_sig_off as usize + cipher.block_size()];
            let count = decrypter.update(
                &file[range_size(0x800, head.footer_sig_off as usize)], 
                &mut decry
            ).unwrap();
            decrypter.finalize(&mut decry).unwrap();
            decry.truncate(count);

            if let Some(path) = &args.outfile {
                if args.dec {
                    let mut newfile = file.to_owned();
                    head.format = 4;
                    struct_write!(head, newfile);
                    newfile[range_size(0x800, head.footer_sig_off as usize)].copy_from_slice(&decry);
                    write_file(path, &newfile);
                } else if args.img2 {
                    write_file(path, &decry);
                }
            }
            parse_img2(&decry, args, &mut is_valid);
        } else {
            parse_img2(&file[range_size(0x800, head.footer_sig_off as usize)], args, &mut is_valid);
        }
    } else {
        unimplemented!("Version 2 IMG1 Headers are not supported yet.");
    }
    if args.verify {
        println!("This image is {}", 
                if is_valid {
                    "valid".green()
                } else {
                    "invalid".red()
                }
        );
    }
}

fn parse_img2(file: &[u8], args: &Args, is_valid: &mut bool) {
    if &file[0..4] != IMG2_HEADER_CIGAM { return }
    let head = cast_struct!(IMG2Header, file);
    if args.all {
        println!("IMG2 Header:\
              \n\tMagic: {},\
              \n\tImage type: {},\
              \n\tRevision: {:#X},\
              \n\tSecurity epoch: {:#X},\
              \n\tLoad address: {:#X},\
              \n\tData size: {:#X},\
              \n\tDecrypted data size: {:#X},\
              \n\tAllocated size: {:#X},\
              \n\tOptions: {},\
              \n\tSignature: {:02X?},\
              \n\tExternel header size: {},\
              \n\tHeader CRC-32: {:#X}",
                  revstr_from_le_bytes(&head.magic),
                  revstr_from_le_bytes(&head.img_type),
                  head.revision,
                  head.sec_epoch,
                  head.load_addr,
                  head.data_size,
                  head.decry_data_size,
                  head.alloc_size,
                  opts(head.opts),
                  head.sig_data,
                  head.extsize,
                  head.header_crc32
        );
    } else if let Some(path) = &args.outfile {
        if !args.dec && !args.img2 {
            write_file(path, &file[range_size(0x400, head.data_size as usize)]);
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
    if head.opts & 1 << 30 != 0 {
        loop {
            let exthead = cast_struct_args!(IMG2ExtHeader, &file[extoff..], (head.extsize, ));
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
            if args.all {
                println!("IMG2 Extension Header:\
                      \n\tCRC-32: {:#x}\
                      \n\tNext extension size: {:#x}\
                      \n\tExtension type: {}\
                      \n\tOptions: {}\
                      \n\tData: {}",
                          exthead.check,
                          exthead.next_size,
                          revstr_from_le_bytes(&exthead.ext_type),
                          opts(exthead.opt),
                          from_utf8(&exthead.data).unwrap()
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

fn parse_img2sb(file: &[u8], args: &Args) {
    let head = cast_struct!(IMG2Superblock, file);
    if args.all {
        println!("IMG2 SuperBlock Header: {:#?}", head);
    }
}

fn checkvalid_decry(buf: &[u8], expected: u32, ext: bool) -> Option<Vec<u8>> {
    let iboottags = [
        0x69_6C_6C_62, // illb
        0x69_62_6F_74, // ibot
        0x69_62_65_63, // ibec
        0x69_62_73_73, // ibss
    ];
    let imagetags = [
        0x6C_6F_67_6F, // logo
        0x72_65_63_6D, // recm
        0x6E_73_72_76, // nsrv
        0x67_6C_79_43, // glyC
        0x67_6C_79_50, // glyP
        0x63_68_67_30, // chg0
        0x63_68_67_31, // chg1
        0x62_61_74_30, // bat0
        0x62_61_74_31, // bat1
        0x62_61_74_46, // batF
    ];
    if &buf[0..8] == b"complzss" && //lzss compressed
       (expected == 0x6B_72_6E_6C || //krnl
        expected == 0x72_6B_72_6E) { //rkrn
        println!("Found compressed kernelcache");
        if !ext {
            let lzsstr = cast_struct!(LZSSHead, buf);
            assert_eq!(&lzsstr.comp_data[0..4], b"\xFF\xCE\xFA\xED");
            let mut decompdata = Vec::with_capacity(lzsstr.decomp_len as usize);
            lzss_decode_block_content(
                &mut Cursor::new(&lzsstr.comp_data), 
                lzsstr.comp_len as u64, 
                &mut decompdata
            ).unwrap_or_else(|e| panic!("Unable to decompress kernelcache: {}", e));
            assert_eq!(decompdata.len(), lzsstr.decomp_len as usize);
            return Some(decompdata);
        }
    } else if (&buf[range_size(0x400, 2)] == b"H+"  //kHFSPlusSigWord
            || &buf[range_size(0x400, 2)] == b"HX") //kHFSXSigWord
            && expected == 0x72_64_73_6B { //rdsk
        println!("Found ramdisk");
    } else if &buf[range_size(0x200, 5)] == b"iBoot" && iboottags.contains(&expected) {
        println!("Found iBoot");
    } else if &buf[0..=7] == b"iBootIm" && imagetags.contains(&expected) { //
        println!("Found iBoot image");
    } else {
        println!("The image may be decrypted with the wrong key or this program does not know this type of image yet. Saving file anyways...");
    }
    None
}

fn parse_img3(mut file: Vec<u8>, args: &Args, argc: usize) {
    let mut head = cast_struct!(IMG3ObjHeader, &file);
    if args.all {
        println!("IMG3 Object Header:\
              \n\tMagic: {},\
              \n\tSkip Distance: {:#x},\
              \n\tBuffer length: {:#x},\
              \n\tSigned length: {:#x},\
              \n\tType: {}", 
              revstr_from_le_bytes(&head.magic), 
              &head.skip_dist, 
              &head.buf_len, 
              &head.signed_len, 
              from_utf8(&head.img3_type.to_be_bytes()).unwrap()
        );
    }
    if let Some(fourcc) = &args.settype {
        assert!(fourcc.len() == 4, "Tag is not length 4");
        head.img3_type = u32::from_be_bytes(fourcc.as_bytes().try_into().unwrap());
        struct_write!(head, file);
    }

    let mut i = 20;
    let mut data: usize = 0x34;
    let mut shshdata = Vec::new();
    while i < head.buf_len as usize {
        let mut taghead = cast_struct!(IMG3TagHeader, &file[i..]);
        let tag = revstr_from_le_bytes(&taghead.tag);
        //dbg!(&tag);
        if args.all {
            println!("IMG3 Tag:\
                  \n\tSkip Distance: {:#x},\
                  \n\tBuffer length: {:#x},", 
                     &taghead.skip_dist, 
                     &taghead.buf_len);
            println!("\tTag type: {} ({})", tag, match tag.as_str() {
                "DATA" => String::from("Data"),
                "SHSH" => String::from("Signed Hash"),
                "CERT" => String::from("Certificate Chain"),
                "VERS" => String::from("Version"),
                "SEPO" => String::from("Security Epoch"),
                "SDOM" => String::from("Security Domain"),
                "PROD" => String::from("Production Status"),
                "CHIP" => String::from("Chip Type"),
                "BORD" => String::from("Board Type"),
                "ECID" => String::from("Unique ID"),
                "SALT" => String::from("Random Pad"),
                "TYPE" => String::from("Type"),
                "OVRD" => String::from("Override"),
                "CEPO" => String::from("Hardware Epoch"),
                "NONC" => String::from("Nonce"),
                "KBAG" => String::from("Keybag"),
                x => format!("Unknown Tag {x:?}")
            });
        }
        //println!("{:x?}", taghead.tag);
        match tag.as_str() {
            "VERS" => {
                let mut vershead = cast_struct!(IMG3TagString, &taghead.buf);
                if args.all || args.ver {
                    println!("{}Version string: {vers}", if args.all {"\t"} else {""}, vers=vershead.str_bytes);
                } else if let Some(vers) = &args.setver {
                    println!("Version was: {oldv}", oldv=vershead.str_bytes);
                    vershead.str_bytes = vers.clone();
                    vershead.str_len = vershead.str_bytes.len() as u32;
                    struct_write!(vershead, taghead.buf);
                    let buf = &taghead.buf.clone();
                    do_resize(&mut taghead, &mut file, i, vershead.str_len + 4, buf);
                    println!("Version is: {vers}", vers=vershead.str_bytes);
                }
            }, "TYPE" => {
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
                    println!("[DEBUG] type in file: {tag}", tag=revstr_from_le_bytes(&taghead.buf));
                }
            }, "OVRD" => {
                /*
                    If you find a IMG3 file containing this tag,
                    pls contact @plzdonthaxme so that I can implement this!
                */
                println!("\tOverride: {ov}", ov=u32::from_le_bytes(taghead.buf.try_into().unwrap()));
            }, "KBAG" => {
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
                    println!("\tIV: {iv}", iv=hex::encode(&keyhead.iv_bytes));
                    println!("\tKey: {key}", key=hex::encode(&keyhead.key_bytes[..ksize]));
                } else if args.keybags {
                    println!("Key type: {}", match keyhead.selector {
                        0 => String::from("Unencrypted"),
                        1 => String::from("Production"),
                        2 => String::from("Development"),
                        x => format!("Unknown ({x:x})")
                    });
                    println!("IV: {iv}", iv=hex::encode(&keyhead.iv_bytes));
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
                    let _ = &file.drain(range_size(i, taghead.skip_dist as usize));
                    continue;
                }
            }, "CERT" => {
                if let Some(path) = &args.savecertpath {
                    write_file(path, &taghead.buf);
                } else if let Some(certpath) = &args.certpath {
                    let certfile = fs::read(certpath).unwrap();
                    let taglen = 12 + (taghead.buf.len() + taghead.pad.len()) as u32;
                    do_resize(&mut taghead, &mut file, i, taglen, &certfile);
                }

                if args.verify {
                    let mut i = 0;
                    let mut is_valid = true;
                    let check = u16::from_be_bytes(taghead.buf[range_size(i, 2)].try_into().unwrap());
                    if check == 0x3082 {
                        let mut certs: Vec<X509> = Vec::new();
                        while i < taghead.buf.len() {
                            let check = u16::from_be_bytes(taghead.buf[range_size(i, 2)].try_into().unwrap());
                            assert_eq!(check, 0x3082);
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
                                    is_valid = false;
                                    println!("{} verification of {cn} with error: {e}", "Failed".red());
                                },
                            }
                        }
                    
                        let leafcert = &certs[certs.len()-1];

                        //CFTypeRef kSecOIDAPPLE_EXTENSION_APPLE_SIGNING = CFSTR("1.2.840.113635.100.6.1.1");
                        //rust's OpenSSL does not implement searching using OID, use memmem instead
                        let haystack = leafcert.to_der().unwrap();
                        if let Some(off) = find(&haystack, b"3gmI") {
                            if args.all {
                                println!("Found Apple certificate signing extension, parsing it");
                                let img3 = cast_struct!(IMG3ObjHeader, &haystack[off..]);
                                parse_img3(haystack[range_size(off, img3.skip_dist as usize)].to_vec(), args, argc);
                            }
                        };

                        let leafpub = leafcert.public_key().unwrap();
                        let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
                        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                        verifier.update(&file[12..20 + head.signed_len as usize]).unwrap();
                        let ok = verifier.verify(&shshdata).unwrap();
                        println!("IMG3 file signature is {}", 
                                if ok {
                                    "valid".green()
                                } else {
                                    is_valid = false;
                                    "invalid".red()
                                }
                        );
                        println!("This image is {}", 
                                if is_valid {
                                    "valid".green()
                                } else {
                                    "invalid".red()
                                }
                        );
                        break;
                    }

                    println!("Found a CERT tag with invalid data, skipping verification");
                    break;
                }
            }, "ECID" => { //number, but this has a uint64 size
                if args.all {
                    println!("\tECID: {}", u64::from_le_bytes(taghead.buf.try_into().unwrap()));
                }
            }, "SDOM" => {
                if args.all {
                    let sdom = u32::from_le_bytes(taghead.buf.try_into().unwrap());
                    println!("\tSecurity Domain: {}", match sdom {
                                x@0 => format!("{x:#x} (Manufacturer)"),
                                x@1 => format!("{x:#x} (Darwin)"),
                                x@3 => format!("{x:#x} (RTXC)"),
                                x => format!("Unknown Security Domain ({x})")
                    });
                }
            }, "DATA" => {
                data = i;
                if let (Some(key), Some(path)) = (&args.key, &args.outfile) {  
                    let padded = [taghead.buf, taghead.pad.clone()].concat(); //this might not be necessary
                    let mut key = key.clone();
                    let iv: String = (&args.iv).clone().unwrap_or_else(|| {
                        let ret = key[..32].to_string();
                        key = key[32..].to_string();
                        ret
                    });
                    let key_bytes: &[u8] = &hex::decode(key.as_bytes()).unwrap();
                    let iv_bytes: &[u8] = &hex::decode(iv.as_bytes()).unwrap();
                    
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
                    decrypter.finalize(&mut buf).unwrap();
                    buf.truncate(count);
                    
                    if args.dec {
                        taghead.buf = buf.clone();
                        struct_write!(taghead, file[i..]);
                    } else {
                        if let Some(data) = checkvalid_decry(&buf, head.img3_type, args.ext) {
                            write_file(path, &data);
                        } else {
                            write_file(path, &buf);
                        }
                        exit(0);
                    }
                } else if argc == 3 {
                    if let Some(path) = &args.outfile {
                        if let Some(data) = checkvalid_decry(&taghead.buf, head.img3_type, args.ext) {
                            write_file(path, &data);
                        } else {
                            write_file(path, &taghead.buf);
                        }
                        exit(0);
                    }
                } else if let Some(datapath) = &args.setdata {
                    let datafile = fs::read(datapath).unwrap();
                    let taglen = 12 + (taghead.buf.len() + taghead.pad.len()) as u32;
                    do_resize(&mut taghead, &mut file, i, taglen, &datafile);
                }
            }, "SHSH" => {
                if let Some(path) = &args.savesigpath {
                    write_file(path, &taghead.buf);
                } else if let Some(sigpath) = &args.sigpath {
                    let hashfile = fs::read(sigpath).unwrap();
                    let taglen = 12 + (taghead.buf.len() + taghead.pad.len()) as u32;
                    do_resize(&mut taghead, &mut file, i, taglen, &hashfile);
                }
                shshdata = taghead.buf;
            }, _ => { //assume number
                if args.all {
                    let num = hex::encode(&taghead.buf.into_iter().rev().collect::<Vec<u8>>());
                    let mut numstr = num.trim_start_matches('0');
                    if numstr.is_empty() {
                        numstr = "0";
                    }
                    println!("\tValue: 0x{}", numstr);
                }
            }
        }
        i += taghead.skip_dist as usize;
        //dbg!(taghead.tag);
        if i >= file.len() {
            break;
        }
    }
    if let Some(path) = &args.outfile {
        write_file(path, &file);
    }
}

fn main() {
    let args = Args::parse();
    let argc = env::args().count();
    let fw: Vec<u8> = fs::read(&args.filename).unwrap_or_else(|e| panic!("Cannot read image, error: {e}"));
    if let Some(create) = &args.create {
        if let Some(op) = &args.outfile {
            let outpath = op.clone();
            match create.as_str() {
                "S5L"  => create_s5l(&fw, &args, &outpath),
                "IMG3" => create_img3(fw, &args, &outpath),
                x => panic!("Invalid image type: {x}")
            }
        } else {
            panic!("No output file specified");
        }
    } else { 
        match fw[..4].try_into().unwrap() {
            S5L8720_HEADER_MAGIC |
            S5L8900_HEADER_MAGIC => parse_s5l(&fw, &args), //8900 / 8970
            IMG2_SB_HEADER_MAGIC => parse_img2sb(&fw, &args), //IMG2
            IMG3_HEADER_CIGAM => parse_img3(fw, &args, argc), //Img3 in le
            x => panic!("Unknown image type with magic: {x:02x?}")
        }
    };
}
