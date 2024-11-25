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

use asn1_rs::{
    oid, Any, FromDer, OctetString, Oid, Sequence, SerializeError, Set, Tag, ToDer
};
use openssl::{hash::MessageDigest, rsa::Padding, sign::Verifier};
use phf::Map;
use std::str;
use colored::Colorize;

use crate::utils::{phf_map, verify_cert, DeviceInfo};

struct IMGTag {
    fullhash: Tag,
    partialhash: Tag,
    trust: Tag,
    build: Tag
}

const TAGMAP: Map<u32, IMGTag> = phf_map! {
    /* IMG3_TAG_CHG0 */ 0x63_68_67_30_u32 => IMGTag { fullhash: Tag(78),  partialhash: Tag(81), trust: Tag(84),  build: Tag(0)  },
    /* IMG3_TAG_CHG1 */ 0x63_68_67_31_u32 => IMGTag { fullhash: Tag(79),  partialhash: Tag(82), trust: Tag(85),  build: Tag(0)  },
    /* IMG3_TAG_BATF */ 0x62_61_74_46_u32 => IMGTag { fullhash: Tag(80),  partialhash: Tag(83), trust: Tag(86),  build: Tag(0)  },
    /* IMG3_TAG_BAT0 */ 0x62_61_74_30_u32 => IMGTag { fullhash: Tag(14),  partialhash: Tag(38), trust: Tag(55),  build: Tag(0)  },
    /* IMG3_TAG_BAT1 */ 0x62_61_74_31_u32 => IMGTag { fullhash: Tag(15),  partialhash: Tag(39), trust: Tag(56),  build: Tag(0)  },
    /* IMG3_TAG_DTRE */ 0x64_74_72_65_u32 => IMGTag { fullhash: Tag(24),  partialhash: Tag(33), trust: Tag(60),  build: Tag(0)  },
    /* IMG3_TAG_DIAG */ 0x64_69_61_67_u32 => IMGTag { fullhash: Tag(11),  partialhash: Tag(35), trust: Tag(52),  build: Tag(0)  },
    /* IMG3_TAG_GLYC */ 0x67_6C_79_43_u32 => IMGTag { fullhash: Tag(12),  partialhash: Tag(36), trust: Tag(53),  build: Tag(0)  },
    /* IMG3_TAG_GLYP */ 0x67_6C_79_50_u32 => IMGTag { fullhash: Tag(13),  partialhash: Tag(37), trust: Tag(54),  build: Tag(0)  },
    /* IMG3_TAG_IBEC */ 0x69_62_65_63_u32 => IMGTag { fullhash: Tag(230), partialhash: Tag(43), trust: Tag(233), build: Tag(22) },
    /* IMG3_TAG_IBOT */ 0x69_62_6F_74_u32 => IMGTag { fullhash: Tag(7),   partialhash: Tag(31), trust: Tag(48),  build: Tag(0)  },
    /* IMG3_TAG_IBSS */ 0x69_62_73_73_u32 => IMGTag { fullhash: Tag(229), partialhash: Tag(42), trust: Tag(232), build: Tag(20) },
    /* IMG3_TAG_ILLB */ 0x69_6C_6C_62_u32 => IMGTag { fullhash: Tag(228), partialhash: Tag(30), trust: Tag(231), build: Tag(6)  },
    /* IMG3_TAG_KRNL */ 0x6B_72_6E_6C_u32 => IMGTag { fullhash: Tag(10),  partialhash: Tag(34), trust: Tag(51),  build: Tag(0)  },
    /* IMG3_TAG_LOGO */ 0x6C_6F_67_6F_u32 => IMGTag { fullhash: Tag(23),  partialhash: Tag(32), trust: Tag(59),  build: Tag(0)  },
    /* IMG3_TAG_RDSK */ 0x72_64_73_6B_u32 => IMGTag { fullhash: Tag(26),  partialhash: Tag(47), trust: Tag(62),  build: Tag(0)  },
    /* IMG3_TAG_RDTR */ 0x72_64_74_72_u32 => IMGTag { fullhash: Tag(9),   partialhash: Tag(45), trust: Tag(50),  build: Tag(0)  },
    /* IMG3_TAG_RECM */ 0x72_65_63_6D_u32 => IMGTag { fullhash: Tag(16),  partialhash: Tag(40), trust: Tag(57),  build: Tag(0)  },
    /* IMG3_TAG_RKRN */ 0x72_6B_72_6E_u32 => IMGTag { fullhash: Tag(25),  partialhash: Tag(46), trust: Tag(61),  build: Tag(0)  },
    /* IMG3_TAG_RLGO */ 0x72_6C_67_6F_u32 => IMGTag { fullhash: Tag(8),   partialhash: Tag(44), trust: Tag(49),  build: Tag(0)  },
};

/// # Panics
/// Panics when the buffer is too small
#[must_use] pub fn partial_sha1(buf: &[u8]) -> Option<Vec<u8>> {
    #[expect(nonstandard_style, dead_code)]
    mod bindings {
        include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    }
    use bindings::{SHA1HashSize, SHA1Input, SHA1Reset, SHA1ResultPartial, shaSuccess};
    
    let signed_len = u32::from_le_bytes(cast_force!(&buf[0..4], [u8; 4]));
    let mut digest = Vec::with_capacity(SHA1HashSize as usize);

    let mut buf = buf.to_owned();

    buf[0..4].copy_from_slice(&(signed_len + 0x40).to_le_bytes());
    let sha_success = i32::try_from(shaSuccess).unwrap();
    unsafe {
        use std::mem::MaybeUninit;
        let mut ctx = MaybeUninit::uninit();
        let ctxptr = ctx.as_mut_ptr();
        let mut ret = SHA1Reset(ctxptr);
        if ret != sha_success {
            println!("SHA1Reset failed, ret: {ret:#X}");
            return None
        };
        ret = SHA1Input(ctxptr, buf.as_ptr(), u32::try_from(buf.len()).unwrap());
        if ret != sha_success {
            println!("SHA1Input failed, ret: {ret:#X}");
            return None
        };
        ret = SHA1ResultPartial(ctxptr, digest.as_mut_ptr());
        if ret != sha_success {
            println!("SHA1Result failed, ret: {ret:#X}");
            return None
        };
        digest.set_len(SHA1HashSize as usize);
    }
    buf[0..4].copy_from_slice(&signed_len.to_le_bytes());

    Some(digest)
} 

/// # Panics
/// Panics when a invalid ``APTicket`` is passed.
#[must_use] pub fn validate(apticket: &[u8]) -> bool {
    println!("Validating APTicket...");
    let (_, is_valid) = Sequence::from_der_and_then(apticket, |d| {
        let mut is_valid = true;
        let (d, ()) = Sequence::from_der_and_then(d, |d| {
            let (left, oid) = Oid::from_der(d)?;
            assert_eq!(oid, oid!(1.2.840.113549.1.1.5), "APTicket is not SHA1 signed"); // sha1withRSAEncryption
            Ok((left, ()))
        })?;
        let (d, data) = Any::from_der(d)?;
        let data = data.to_der_vec().map_err(|x| 
            if let SerializeError::ASN1Error(asnerr) = x {
                asnerr
            } else {
                panic!("Failed to convert to DER vector with error: {x}");
            }
        )?;
        let (d, sig) = OctetString::from_der(d)?;
        let sig = sig.as_cow();
        let (d, certs) = Any::from_der(d)?;
        let certs = certs.data;
        let leafcert = verify_cert(certs, &mut is_valid);
        // TODO: parse leafcert 1.2.840.113635.100.6.1.11 extension
        let leafpub = leafcert.public_key().unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha1(), &leafpub).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        verifier.update(&data).unwrap();
        let is_ok = verifier.verify(sig).unwrap();
        println!("APTicket signature is {}", 
                if is_ok {
                    "valid".green()
                } else {
                    is_valid = false;
                    "invalid".red()
                }
        );
        Ok((d, is_valid))
    }).unwrap();
    is_valid
}

/// # Panics
/// This function can panic when a invalid ``APTicket`` is passed.
pub fn parse(apticket: &[u8], tag: u32, fullsha1: &[u8], partialsha1: &[u8], imgvers: Option<&str>, is_valid: &mut bool) -> (DeviceInfo, Option<[u8; 20]>) {
    //println!("{}", hex::encode(partialsha1));
    let mut dfo = DeviceInfo::default();
    let (_, nonce) = Sequence::from_der_and_then(apticket, |d| {
        let (d, _) = Any::from_der(d)?; // ign
        Set::from_der_and_then(d, |d| {
            let mut d = d;
            let IMGTag { fullhash, partialhash, trust, build } = TAGMAP[&tag];
            let mut res: (&[u8], Option<[u8; 20]>) = (&[], None);
            let mut val = true;
            let mut can_trust = true;
            let mut saw_digest = false;
            while let Ok((i, cur)) = Any::from_der(d) {// Parse context-specific like this
                match cur.tag() {
                    Tag(1) => {     // ECID
                        dfo.ecid = Some(u64::from_le_bytes(cur.as_bytes().try_into().unwrap()));
                    }, Tag(2) => { // CPID
                        dfo.cpid = Some(u32::from_le_bytes(cur.as_bytes().try_into().unwrap()));
                    }, Tag(3) => { // BORD
                        dfo.bdid = Some(vec![u32::from_le_bytes(cur.as_bytes().try_into().unwrap())]);
                    }, Tag(4) => { // PROD
                        dfo.prod = Some(u32::from_le_bytes(cur.as_bytes().try_into().unwrap()));
                    }, Tag(5) => { // SDOM
                        dfo.sdom = Some(u32::from_le_bytes(cur.as_bytes().try_into().unwrap()));
                    }, Tag(18) => { // NONC
                        let vec = Some(cur.as_bytes().to_owned().try_into().unwrap());
                        res = (i, vec);
                    }, x if x == fullhash => {
                        //println!("Digest: {}", hex::encode(cur.as_bytes()));
                        //dbg!(hex::encode(fullsha1), hex::encode(cur.as_bytes()));
                        if fullsha1 == cur.as_bytes() {
                            println!("Digest {}", "matches".green());
                        } else {
                            println!("Digest does {} match", "not".red());
                            val = false;
                        }
                        saw_digest = true;
                    }, x if x == partialhash => {
                        //println!("Partial Digest: {}", hex::encode(cur.as_bytes()));
                        //dbg!(hex::encode(partialsha1), hex::encode(cur.as_bytes()));
                        if partialsha1 == cur.as_bytes() {
                            println!("Partial Digest {}", "matches".green());
                        } else {
                            println!("Partial Digest does {} match", "not".red());
                            val = false;
                        }
                        saw_digest = true;
                    }, x if x == trust => {
                        println!("Trusted Component: {}", 
                            if u32::from_le_bytes(cast_force!(cur.as_bytes(), [u8; 4])) == 1 { 
                                "True" 
                            } else { 
                                can_trust = false;
                                "False (ignoring mismatched values)"
                            }
                        );
                        if u32::from_le_bytes(cast_force!(cur.as_bytes(), [u8; 4])) != 1 {
                            can_trust = false;
                        }
                    }, x if x == build => {
                        if let Some(imgvers) = imgvers {
                            let vers = str::from_utf8(cur.as_bytes()).unwrap();
                            //println!("Version: {vers}");
                            if (vers.contains('~') && vers.split('~').next().unwrap() == imgvers) || vers == imgvers {
                                println!("Version {}", "matches".green());
                            } else {
                                println!("Version does {} match", "not".red());
                                val = false;
                            }
                        } else {
                            println!("Version does {} exist", "not".red());
                            val = false;
                        }
                    },
                    _ => {}
                }
                d = i;
            }
            if can_trust {
                if !saw_digest {
                    println!("Digest unseen in APTicket, invalidating...");
                    val = false;
                }
                *is_valid = val;
            }
            Ok(res)
        })
    }).unwrap();
    //println!("NONC: {}", hex::encode(nonce));
    (dfo, nonce)
}