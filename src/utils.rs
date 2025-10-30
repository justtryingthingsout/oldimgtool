/*
    oldimgtool - A IMG1/2/3 parser and a NOR dump parser
    Copyright (C) 2025 plzdonthaxme

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

pub use {
    crate::lzss::*,
    asn1_rs::{FromDer, Sequence, ToDer},
    binrw::BinReaderExt,
    binrw::{binrw, io::Cursor, BinRead, BinWrite},
    colored::Colorize,
    lazy_static::lazy_static,
    openssl::{nid::Nid, string::OpensslString, x509::X509},
    phf::phf_map, //static map because I know all the values
    std::{
        borrow::Cow, collections::HashMap, error::Error, fmt, fs::write, ops::Range, str::from_utf8,
    },
};

//utility macros

//cast to type, panicking if unable to do so
#[macro_export]
macro_rules! cast_force {
    ($e: expr, $t: ty) => {
        TryInto::<$t>::try_into($e)
            .unwrap_or_else(|_| panic!("Unable to cast to {}", stringify!($t)))
    };
}

//generate a struct from a slice of bytes, using binrw
#[macro_export]
macro_rules! cast_struct {
    ($t: ty, $arr: expr) => {
        Cursor::new($arr).read_le::<$t>().unwrap_or_else(|e| {
            panic!(
                "Unable to deserialize to {}, err: {e}, first 4 bytes: {bytes:x?}",
                stringify!($t),
                bytes = &$arr[0..4]
            )
        })
    };
}

//generate a struct from a slice of bytes with imported arguments, using binrw
#[macro_export]
macro_rules! cast_struct_args {
    ($t: ty, $arr: expr, $args: expr) => {
        <$t>::read_args(&mut Cursor::new($arr), $args).unwrap_or_else(|e| {
            panic!(
                "Unable to deserialize to {}, err: {e}, first 4 bytes: {bytes:x?}",
                stringify!($t),
                bytes = &$arr[0..4]
            )
        })
    };
}

//write a binrw struct to a mutable buffer
#[macro_export]
macro_rules! struct_write {
    ($str: expr, $arr: expr) => {
        $str.write(&mut Cursor::new(&mut $arr))
            .unwrap_or_else(|e| panic!("Unable to write to buffer: {e}"));
    };
}

//utility functions

//get the first common name in a X509Certificate
/// # Panics
/// Panics if the certificate has no common name
#[must_use]
pub fn get_cn(cert: &X509) -> OpensslString {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|x| x.data().as_utf8().ok())
        .unwrap()
}

const APPLE_ROOT_CERT: &[u8; 1215] = include_bytes!("Apple_Root_CA.cer");

/// # Panics
/// Panics if certificates are invalid
pub fn verify_cert(certbuf: &[u8], is_valid: &mut bool) -> X509 {
    let mut certs: Vec<X509> = Vec::new();
    let mut i = 0;
    while i < certbuf.len() {
        let cert = X509::from_der(&certbuf[i..]).expect("Found invalid certificate");
        i += cert.to_der().unwrap().len(); // this unwrap should never fail, it comes from a DER
        certs.push(cert);
    }

    // sorting of the certificate chain because some ipod fws have it upside down
    let mut swap = false;
    let mut found = false;
    // get root node
    for i in 0..certs.len() {
        if certs[i].issuer_name_hash() == certs[i].subject_name_hash() {
            found = true;
            if i != 0 {
                swap = true;
                certs.swap(0, i);
            }
            break;
        }
    }

    if !found {
        certs.insert(0, X509::from_der(APPLE_ROOT_CERT).unwrap()); // some images don't have builtin root certs
    }

    if swap && certs.len() > 2 {
        let mut last = 0;
        // add leafs
        while last != certs.len() - 1 {
            for i in last + 1..certs.len() {
                if certs[i].issuer_name_hash() == certs[last].subject_name_hash() {
                    last += 1;
                    certs.swap(i, last);
                    break;
                }
            }
        }
    }

    if found {
        println!("Assuming \"{}\" is trusted", get_cn(&certs[0]));
    } else {
        println!("Using built-in Apple Root CA certificate as no root CAs were found.");
    }

    for i in 1..certs.len() {
        // skip root
        let cn = get_cn(&certs[i]);
        match certs[i].verify(&certs[i - 1].public_key().unwrap()) {
            Ok(x) => {
                if x {
                    println!("Certificate \"{cn}\" is {}", "valid".green());
                } else {
                    println!("{} verification of \"{cn}\"", "Failed".red());
                    *is_valid = false;
                }
            }
            Err(e) => {
                println!(
                    "{} verification of \"{cn}\" with error: {e}",
                    "Failed".red()
                );
                *is_valid = false;
            }
        }
    }
    certs.pop().unwrap() // returns leaf
}

//write a buffer to a file with the specified path
/// # Panics
/// Panics if the file cannot be written into
pub fn write_file(path: &str, arr: &[u8]) {
    write(path, arr).unwrap_or_else(|e| panic!("Unable to write to \"{path}\": {e}"));
}

//create a range from the start and size
#[must_use]
pub const fn range_size(start: usize, size: usize) -> Range<usize> {
    start..start + size
}

//make a reversed string from bytes
/// # Panics
/// Panics if the bytes are not valid utf8
#[must_use]
pub fn revstr_from_le_bytes(arr: &[u8]) -> String {
    from_utf8(arr)
        .unwrap_or_else(|_| panic!("{arr:?}"))
        .chars()
        .rev()
        .collect::<String>()
}

pub fn print_unknown_val(args: &crate::Args, taghead: &IMG3TagHeader) {
    if args.all {
        let num = hex::encode(taghead.buf.clone().into_iter().rev().collect::<Vec<u8>>());
        let mut numstr = num.trim_start_matches('0');
        if numstr.is_empty() {
            numstr = "0";
        }
        println!("\tValue: 0x{numstr}");
    }
}

//resize buffer and pad to a 4 byte boundary, deleting or inserting bytes as
// needed
pub fn do_resize(
    mainhead: &mut IMG3ObjHeader,
    head: &mut IMG3TagHeader,
    file: &mut Vec<u8>,
    off: usize,
    taglen: u32,
    newdat: Vec<u8>,
) {
    let oldbuflen = head.buf_len;
    let newbuflen = taglen;

    let newlen = newdat.len();
    head.buf = newdat;
    head.buf_len = taglen;

    match oldbuflen.cmp(&newbuflen) {
        std::cmp::Ordering::Greater => {
            file.drain(range_size(
                off + 12 + head.buf_len as usize,
                (oldbuflen - newbuflen) as usize,
            ));
        }
        std::cmp::Ordering::Less => {
            file.splice(
                range_size(off + 12 + oldbuflen as usize, 0),
                vec![0; (newbuflen - oldbuflen) as usize],
            );
        }
        std::cmp::Ordering::Equal => {}
    }

    //fix padding
    let oldpadlen = head.pad.len();
    head.pad.resize(newlen % 4, 0); //needs to be on a 4 byte boundary
    let newpadlen = head.pad.len();
    match oldpadlen.cmp(&newpadlen) {
        std::cmp::Ordering::Greater => {
            file.drain(range_size(
                off //offset of tag
                                        + 12 //size of header
                                        + head.buf_len as usize //size of data
                                        + newpadlen, //size of padding
                oldpadlen - newpadlen, //difference in padding size
            ));
        }
        std::cmp::Ordering::Less => {
            file.splice(
                range_size(off + 12 + oldpadlen, 0),
                vec![0; newpadlen - oldpadlen],
            );
        }
        std::cmp::Ordering::Equal => {}
    }
    head.skip_dist = 12 //size of header
                     + newbuflen //size of data
                     + cast_force!(newpadlen, u32); //size of padding
    let chg = oldbuflen - newbuflen;
    mainhead.buf_len -= chg;
    mainhead.skip_dist -= chg;

    struct_write!(head, file[off..]);
    struct_write!(mainhead, file[0..]);
}

pub const PLAUSABLE_PKCS1: [u8; 10] = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

pub const LZSS_MAGIC: [u8; 8] = *b"complzss";

pub const IMG3_TAG_BAT0: u32 = 0x62_61_74_30; // bat0
pub const IMG3_TAG_BAT1: u32 = 0x62_61_74_31; // bat1
pub const IMG3_TAG_BATF: u32 = 0x62_61_74_46; // batF
pub const IMG3_TAG_CHG0: u32 = 0x63_68_67_30; // chg0
pub const IMG3_TAG_CHG1: u32 = 0x63_68_67_31; // chg1
pub const IMG3_TAG_DTRE: u32 = 0x64_74_72_65; // dtre
pub const IMG3_TAG_DIAG: u32 = 0x64_69_61_67; // diag
pub const IMG3_TAG_GLYC: u32 = 0x67_6C_79_43; // glyC
pub const IMG3_TAG_GLYP: u32 = 0x67_6C_79_50; // glyP
pub const IMG3_TAG_IBEC: u32 = 0x69_62_65_63; // ibec
pub const IMG3_TAG_IBOT: u32 = 0x69_62_6F_74; // ibot
pub const IMG3_TAG_IBSS: u32 = 0x69_62_73_73; // ibss
pub const IMG3_TAG_ILLB: u32 = 0x69_6C_6C_62; // illb
pub const IMG3_TAG_KRNL: u32 = 0x6B_72_6E_6C; // krnl
pub const IMG3_TAG_LOGO: u32 = 0x6C_6F_67_6F; // logo
pub const IMG3_TAG_NSRV: u32 = 0x6E_73_72_76; // nsrv
pub const IMG3_TAG_RDSK: u32 = 0x72_64_73_6B; // rdsk
pub const IMG3_TAG_RDTR: u32 = 0x72_64_74_72; // rdtr
pub const IMG3_TAG_RECM: u32 = 0x72_65_63_6D; // recm
pub const IMG3_TAG_RKRN: u32 = 0x72_6B_72_6E; // rkrn
pub const IMG3_TAG_RLGO: u32 = 0x72_6C_67_6F; // rlgo

pub const IMG3_TAG_CERT: u32 = 0x63_65_72_74; // cert (special, in kSecOIDAPPLE_EXTENSION_APPLE_SIGNING)
pub const IMG3_TAG_SCAB: u32 = 0x53_43_41_42; // scab (special, APTicket stored in NOR)

pub const HFS_PLUS_SIG_WORD: &[u8; 2] = b"H+"; //kHFSPlusSigWord
pub const HFSX_SIG_WORD: &[u8; 2] = b"HX"; //kHFSXSigWord

/// # Panics
/// Panics if lzss failed to decompress
#[must_use]
pub fn checkvalid_decry(buf: &[u8], expected: u32, ext: bool) -> Option<Vec<u8>> {
    let iboottags = [IMG3_TAG_ILLB, IMG3_TAG_IBOT, IMG3_TAG_IBEC, IMG3_TAG_IBSS];
    let imagetags = [
        IMG3_TAG_LOGO,
        IMG3_TAG_RECM,
        IMG3_TAG_NSRV,
        IMG3_TAG_GLYC,
        IMG3_TAG_GLYP,
        IMG3_TAG_CHG0,
        IMG3_TAG_CHG1,
        IMG3_TAG_BAT0,
        IMG3_TAG_BAT1,
        IMG3_TAG_BATF,
    ];
    if buf[0..8] == LZSS_MAGIC && //lzss compressed
       (expected == IMG3_TAG_KRNL ||
        expected == IMG3_TAG_RKRN)
    {
        println!("Found compressed kernelcache");
        if !ext {
            let lzsstr = cast_struct!(LZSSHead, buf);
            assert_eq!(&lzsstr.comp_data[0..4], b"\xFF\xCE\xFA\xED");
            return Some(
                decompress(&lzsstr.comp_data, lzsstr.decomp_len, lzsstr.adler32)
                    .unwrap_or_else(|| panic!("Adler32 mismatch when decompressing kernelcache")),
            );
        }
    } else if (&buf[range_size(0x400, 2)] == HFS_PLUS_SIG_WORD
        || &buf[range_size(0x400, 2)] == HFSX_SIG_WORD)
        && expected == IMG3_TAG_RDSK
    {
        println!("Found ramdisk");
    } else if u32::from_le_bytes(buf[0..4].try_into().unwrap()) < 0x100
        && (expected == IMG3_TAG_DTRE || expected == IMG3_TAG_RDTR)
    {
        println!("Found devicetree");
    } else if (&buf[range_size(0x200, 5)] == b"iBoot"
        || &buf[range_size(0x200, 4)] == b"iBSS"
        || &buf[range_size(0x200, 4)] == b"iBEC"
        || &buf[range_size(0x200, 3)] == b"LLB")
        && iboottags.contains(&expected)
    {
        println!("Found iBoot");
    } else if &buf[0..7] == b"iBootIm" && imagetags.contains(&expected) {
        println!("Found iBoot image");
    } else if iboottags.contains(&expected)
        || imagetags.contains(&expected)
        || [
            IMG3_TAG_KRNL,
            IMG3_TAG_RKRN,
            IMG3_TAG_RDSK,
            IMG3_TAG_DTRE,
            IMG3_TAG_RDTR,
        ]
        .contains(&expected)
    {
        println!("The image may be decrypted with the wrong key. Saving the file anyways...");
    }
    None
}

#[must_use]
pub fn format_type(value: u8) -> String {
    match value {
        1 => Cow::from("Boot Encrypted with UID key"),
        2 => Cow::from("Boot Plaintext"),
        3 => Cow::from("Encrypted with GID key"),
        4 => Cow::from("Plaintext"),
        _ => Cow::from(format!("Unknown Format ({value})")),
    }
    .to_string()
}

#[must_use]
pub fn override_types(value: u32) -> String {
    if value & (1 << 0) == 0 {
        String::from("No Override")
    } else {
        String::from("Production Override")
    }
}

//pub const IMG2_OPT_SIGNATURE_TYPE_EXTERNAL:      u32 = 1<<0;
//pub const IMG2_OPT_SIGNATURE_TYPE_INTERNAL_SHA1: u32 = 1<<1;
//pub const IMG2_OPT_SIGNATURE_TYPE_INTERNAL_CRC:  u32 = 1<<2;
//pub const IMG2_OPT_TRUSTED_IMAGE:                u32 = 1<<8;
pub const IMG2_OPT_ENCRYPTED_IMAGE: u32 = 1 << 9;
//pub const IMG2_OPT_INSTALLED_WITH_SB:            u32 = 1<<24;
pub const IMG2_OPT_EXTENSION_PRESENT: u32 = 1 << 30;
//pub const IMG2_OPT_IMMUTABLE:                    u32 = 1<<31;

pub static OPTMAP: phf::Map<u32, &'static str> = phf_map! {
    0u32 => "External Signature",
    1u32 => "SHA1 in Signature Data",
    2u32 => "CRC32 in Signature Data",
    8u32 => "Trusted Image",
    9u32 => "Encrypted Image",
    24u32 => "Image with Secure Boot",
    30u32 => "With Extension Header",
    31u32 => "Immutable"
};

#[must_use]
pub fn opts(val: u32) -> String {
    if val == 0 {
        return String::from("No Options");
    }
    OPTMAP
        .entries()
        .filter(|i| val & (1 << i.0) != 0)
        .map(|i| *i.1)
        .collect::<Vec<&str>>()
        .join(", ")
}

#[binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct S5LHeader {
    pub platform: [u8; 4],
    pub version: [u8; 3],
    pub format: u8,
    pub entry: u32,
    pub size_of_data: u32,
    pub footer_sig_off: u32,
    pub footer_cert_off: u32,
    pub footer_cert_len: u32,
    pub salt: [u8; 0x20],
    pub unknown2: u16,
    pub epoch: u16,
    pub header_signature: [u8; 0x10],
    pub unencrypted_sig: [u8; 4],
}

impl fmt::Display for S5LHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "S5L Header:\n\tPlatform: {},\n\tVersion: {},\n\tFormat: {},\n\tEntry: {:#X},\n\tSize \
             of Data: {:#X},\n\tFooter Signature Offset: {:#X},\n\tFooter Certificate Offset: \
             {:#X},\n\tFooter Certificate Length: {:#X},\n\tSalt: {:02X?},\n\tEpoch: \
             {:#X},\n\tHeader Signature: {:02X?}{}",
            from_utf8(&self.platform).unwrap(),
            from_utf8(&self.version).unwrap(),
            format_type(self.format),
            self.entry,
            self.size_of_data,
            self.footer_sig_off,
            self.footer_cert_off,
            self.footer_cert_len,
            self.salt,
            self.epoch,
            self.header_signature,
            if self.unencrypted_sig == [0; 4] {
                String::new()
            } else {
                format!(",\n\tUnencrypted signature: {:02X?}", self.unencrypted_sig)
            }
        )
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct IMG2Header {
    pub magic: [u8; 4],
    pub img_type: [u8; 4],
    pub revision: u16,
    pub sec_epoch: u16,
    pub load_addr: u32,
    pub data_size: u32,
    pub decry_data_size: u32,
    pub alloc_size: u32,
    pub opts: u32,
    pub sig_data: [u8; 0x40],
    pub extsize: u32,
    pub header_crc32: u32,
}

impl Default for IMG2Header {
    fn default() -> Self {
        Self {
            magic: [0; 4],
            img_type: [0; 4],
            revision: 0,
            sec_epoch: 0,
            load_addr: 0,
            data_size: 0,
            decry_data_size: 0,
            alloc_size: 0,
            opts: 0,
            sig_data: [0; 0x40],
            extsize: 0,
            header_crc32: 0,
        }
    }
}

impl fmt::Display for IMG2Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IMG2 Header:\n\tMagic: {}\n\tImage Type: {}\n\tRevision: {:#X}\n\tSecurity Epoch: \
             {:#X}\n\tLoad Address: {:#X}\n\tData Size: {:#X}\n\tDecrypted Data Size: \
             {:#X}\n\tAllocated Size: {:#X}\n\tOptions: {}\n\tSignature: {:02X?}\n\tExternal \
             Header Size: {:#X}\n\tHeader CRC-32: {:#X}",
            revstr_from_le_bytes(&self.magic),
            revstr_from_le_bytes(&self.img_type),
            self.revision,
            self.sec_epoch,
            self.load_addr,
            self.data_size,
            self.decry_data_size,
            self.alloc_size,
            opts(self.opts),
            self.sig_data,
            self.extsize,
            self.header_crc32
        )
    }
}

type Img2HeaderExtensionType = [u8; 4];

#[binrw]
#[br(little, import(cur_size: u32))]
#[bw(little)]
#[derive(Default, Debug)]
pub struct IMG2ExtHeader {
    pub check: u32,     /* CRC-32 of the succeeding fields */
    pub next_size: u32, /* Size in bytes of the next extension */
    pub ext_type: Img2HeaderExtensionType,
    pub opt: u32,
    #[br(count = cur_size)]
    pub data: Vec<u8>, /* Extension data. */
}

impl fmt::Display for IMG2ExtHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IMG2 Extension Header:\n\tCheck: {:#X}\n\tNext Size: {:#X}\n\tExtension Type: \
             {}\n\tOptions: {}\n\tData: {}",
            self.check,
            self.next_size,
            revstr_from_le_bytes(&self.ext_type),
            opts(self.opt),
            from_utf8(&self.data).unwrap()
        )
    }
}

#[binrw]
#[brw(little)]
#[derive(Default, Debug)]
pub struct IMG2Superblock {
    pub magic: [u8; 4],
    pub image_granule: u32,  // fundamental block size (bytes)
    pub image_offset: u32,   // image header offset within granule (image granules)
    pub boot_blocksize: u32, // size of the bootblock (image granules)
    pub image_avail: u32,    // total granules available for images
    pub nvram_granule: u32,  // size of NVRAM blocks (bytes)
    pub nvram_offset: u32,   // offset to first NVRAM block (nvram granules)
    flags: u32,              // flags field reserved for future use
    rsvd1: u32,              // reserved 1 for future use
    rsvd2: u32,              // reserved 2 for future use
    rsvd3: u32,              // reserved 3 for future use
    rsvd4: u32,              // reserved 4 for future use
    pub check: u32,          // CRC-32 of header fields preceding this one
}

impl fmt::Display for IMG2Superblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IMG2 Superblock Header: \n\t Magic: {}\n\t Image Granule Size: {:#X}\n\t Image \
             Header Offset: {:#X}\n\t Boot Blocksize: {:#X}\n\t Total Granules: {:#X}\n\t NVRAM \
             Granules: {:#X}\n\t NVRAM Offset: {:#X}\n\t Header CRC32: {:#X}",
            revstr_from_le_bytes(&self.magic),
            self.image_granule,
            self.image_offset,
            self.boot_blocksize,
            self.image_avail,
            self.nvram_granule,
            self.nvram_offset,
            self.check
        )
    }
}

pub const S5L8442_HEADER_MAGIC: [u8; 4] = *b"8442";
pub const S5L8443_HEADER_MAGIC: [u8; 4] = *b"8443";
pub const S5L8702_HEADER_MAGIC: [u8; 4] = *b"8702";
pub const S5L8720_HEADER_MAGIC: [u8; 4] = *b"8720";
pub const S5L8723_HEADER_MAGIC: [u8; 4] = *b"8723";
pub const S5L8730_HEADER_MAGIC: [u8; 4] = *b"8730";
pub const S5L8740_HEADER_MAGIC: [u8; 4] = *b"8740";
pub const S5L8900_HEADER_MAGIC: [u8; 4] = *b"8900";
pub const IMG1_PLATFORMS: [[u8; 4]; 8] = [
    S5L8443_HEADER_MAGIC,
    S5L8442_HEADER_MAGIC,
    S5L8702_HEADER_MAGIC,
    S5L8720_HEADER_MAGIC,
    S5L8723_HEADER_MAGIC,
    S5L8730_HEADER_MAGIC,
    S5L8740_HEADER_MAGIC,
    S5L8900_HEADER_MAGIC,
];

pub const IMG2_SB_HEADER_CIGAM: [u8; 4] = *b"2GMI";
pub const IMG2_HEADER_CIGAM: [u8; 4] = *b"2gmI";
pub const IMG3_HEADER_CIGAM: [u8; 4] = *b"3gmI";

pub const SIGNED_ENCRYPT: u8 = 1;
pub const SIGNED: u8 = 2;
pub const X509_SIGNED_ENCRYPTED: u8 = 3;
pub const X509_SIGNED: u8 = 4;

pub const IMG1_FORMAT_1: [u8; 3] = *b"1.0";
pub const IMG1_FORMAT_2: [u8; 3] = *b"2.0";

pub const IMG3_GAT_DATA: [u8; 4] = *b"ATAD";
pub const IMG3_GAT_SIGNED_HASH: [u8; 4] = *b"HSHS";
pub const IMG3_GAT_CERTIFICATE_CHAIN: [u8; 4] = *b"TREC";
pub const IMG3_GAT_VERSION: [u8; 4] = *b"SREV";
//pub const IMG3_GAT_SECURITY_EPOCH:    [u8; 4]    = *b"OPES";
//pub const IMG3_GAT_SECURITY_DOMAIN:   [u8; 4]    = *b"MODS";
//pub const IMG3_GAT_PRODUCTION_STATUS: [u8; 4]    = *b"DORP";
//pub const IMG3_GAT_CHIP_TYPE:         [u8; 4]    = *b"PIHC";
//pub const IMG3_GAT_BOARD_TYPE:        [u8; 4]    = *b"DROB";
pub const IMG3_GAT_UNIQUE_ID: [u8; 4] = *b"DICE";
//pub const IMG3_GAT_RANDOM_PAD:        [u8; 4]    = *b"TLAS";
pub const IMG3_GAT_RANDOM: [u8; 4] = *b"DNAR";
pub const IMG3_GAT_TYPE: [u8; 4] = *b"EPYT";
//pub const IMG3_GAT_OVERRIDE:          [u8; 4]    = *b"DRVO";
//pub const IMG3_GAT_HARDWARE_EPOCH:    [u8; 4]    = *b"OPEC";
//pub const IMG3_GAT_NONCE:             [u8; 4]    = *b"CNON";
pub const IMG3_GAT_KEYBAG: [u8; 4] = *b"GABK";

pub const IMG3_TAG_DATA: &str = "DATA";
pub const IMG3_TAG_SIGNED_HASH: &str = "SHSH";
pub const IMG3_TAG_CERTIFICATE_CHAIN: &str = "CERT";
pub const IMG3_TAG_VERSION: &str = "VERS";
pub const IMG3_TAG_SECURITY_EPOCH: &str = "SEPO";
pub const IMG3_TAG_SECURITY_DOMAIN: &str = "SDOM";
pub const IMG3_TAG_PRODUCTION_STATUS: &str = "PROD";
pub const IMG3_TAG_CHIP_TYPE: &str = "CHIP";
pub const IMG3_TAG_BOARD_TYPE: &str = "BORD";
pub const IMG3_TAG_UNIQUE_ID: &str = "ECID";
pub const IMG3_TAG_RANDOM_PAD: &str = "SALT";
pub const IMG3_TAG_RANDOM: &str = "RAND";
pub const IMG3_TAG_TYPE: &str = "TYPE";
pub const IMG3_TAG_OVERRIDE: &str = "OVRD";
pub const IMG3_TAG_HARDWARE_EPOCH: &str = "CEPO";
pub const IMG3_TAG_NONCE: &str = "NONC";
pub const IMG3_TAG_KEYBAG: &str = "KBAG";

//pub const APPLE_CERT_SHA512: &str =
// "5621f576006af21c100ab091653762ccc72e66caadb5b61235ef2d91595cbcf897c449353e9ce818c97ab2a8ee938c7204ea38887cb4eb8e8cff3234edbcc65b"
// ;

pub const KEY_837: &[u8; 16] = b"\x18\x84\x58\xA6\xD1\x50\x34\xDF\xE3\x86\xF2\x3B\x61\xD4\x37\x74";

#[binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct IMG3ObjHeader {
    // these fields are unsigned
    pub magic: [u8; 4],
    pub skip_dist: u32,
    pub buf_len: u32,

    // these fields are signed
    pub signed_len: u32,
    pub img3_type: u32,
    //Vec<IMG3TagHeaders> follow
}

impl fmt::Display for IMG3ObjHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IMG3 Object Header:\n\tMagic: {},\n\tSkip Distance: {:#x},\n\tBuffer Length: \
             {:#x},\n\tSigned Length: {:#x},\n\tType: {}",
            revstr_from_le_bytes(&self.magic),
            &self.skip_dist,
            &self.buf_len,
            &self.signed_len,
            from_utf8(&self.img3_type.to_be_bytes()).unwrap()
        )
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Default, Clone)]
pub struct IMG3TagHeader {
    pub tag: [u8; 4],
    pub skip_dist: u32,
    pub buf_len: u32,
    #[br(count = buf_len)]
    pub buf: Vec<u8>,
    #[br(count = skip_dist - buf_len - 12)]
    pub pad: Vec<u8>,
}

fn tagtype(tag: [u8; 4]) -> Cow<'static, str> {
    match revstr_from_le_bytes(&tag).as_str() {
        "DATA" => Cow::from("Data"),
        "SHSH" => Cow::from("Signed Hash"),
        "CERT" => Cow::from("Certificate Chain"),
        "VERS" => Cow::from("Version"),
        "SEPO" => Cow::from("Security Epoch"),
        "SDOM" => Cow::from("Security Domain"),
        "PROD" => Cow::from("Production Status"),
        "CHIP" => Cow::from("Chip Type"),
        "BORD" => Cow::from("Board Type"),
        "ECID" => Cow::from("Unique ID"),
        "SALT" => Cow::from("Random Pad"),
        "RAND" => Cow::from("Random"),
        "TYPE" => Cow::from("Type"),
        "OVRD" => Cow::from("Override"),
        "CEPO" => Cow::from("Hardware Epoch"),
        "NONC" => Cow::from("Nonce"),
        "KBAG" => Cow::from("Keybag"),
        x => Cow::from(format!("Unknown Tag {x:?}")),
    }
}

impl fmt::Display for IMG3TagHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IMG3 Tag:\n\tTag: {} ({}),\n\tSkip Distance: {:#x},\n\tBuffer Length: {:#x},",
            revstr_from_le_bytes(&self.tag),
            tagtype(self.tag),
            &self.skip_dist,
            &self.buf_len
        )
    }
}

#[binrw]
#[derive(Debug)]
#[brw(little)]
pub struct IMG3TagString {
    /* number of valid bytes in the buffer */
    pub str_len: u32,
    #[br(count(str_len), map = |s: Vec<u8>| String::from_utf8(s).unwrap())]
    #[bw(map = String::as_bytes)]
    pub str_bytes: String,
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct IMG3KBAG {
    pub selector: u32,
    pub key_size: u32,
    pub iv_bytes: [u8; 0x10],
    pub key_bytes: [u8; 0x20],
}

#[binrw]
#[brw(big)]
#[derive(Debug)]
pub struct LZSSHead {
    pub magic: [u8; 8],
    pub adler32: u32,
    pub decomp_len: u32,
    pub comp_len: u32,
    pub vers: u32,
    #[br(count = 360)]
    pub pad: Vec<u8>,
    #[br(count = comp_len)]
    pub comp_data: Vec<u8>,
}

lazy_static! {
    static ref BOARDMAP: HashMap<(u32, u32), (&'static str, &'static str, &'static str)> = vec![
        ((0x00, 0x8900), ("iPhone 2G",                                          "iPhone1,1",   "m68ap")),
        ((0x01, 0x8900), ("iPhone 2G Development Board",                        "iPhone1,1",   "m68dev")),
        ((0x04, 0x8900), ("iPhone 3G",                                          "iPhone1,2",   "n82ap")),
        ((0x05, 0x8900), ("iPhone 3G Development Board",                        "iPhone1,2",   "n82dev")),
        ((0x00, 0x8920), ("iPhone 3GS",                                         "iPhone2,1",   "n88ap")),
        ((0x01, 0x8920), ("iPhone 3GS Development Board",                       "iPhone2,1",   "n88dev")),
        ((0x00, 0x8930), ("iPhone 4 (GSM)",                                     "iPhone3,1",   "n90ap")),
        ((0x01, 0x8930), ("iPhone 4 (GSM) Development Board",                   "iPhone3,1",   "n90dev")),
        ((0x04, 0x8930), ("iPhone 4 (GSM) R2 2012",                             "iPhone3,2",   "n90bap")),
        ((0x05, 0x8930), ("iPhone 4 (GSM) R2 2012 Development Board",           "iPhone3,2",   "n90bdev")),
        ((0x06, 0x8930), ("iPhone 4 (CDMA)",                                    "iPhone3,3",   "n92ap")),
        ((0x07, 0x8930), ("iPhone 4 (CDMA) Development Board",                  "iPhone3,3",   "n92dev")),
        ((0x08, 0x8940), ("iPhone 4S",                                          "iPhone4,1",   "n94ap")),
        ((0x09, 0x8940), ("iPhone 4S Development Board",                        "iPhone4,1",   "n94dev")),
        ((0x00, 0x8950), ("iPhone 5 (GSM)",                                     "iPhone5,1",   "n41ap")),
        ((0x01, 0x8950), ("iPhone 5 (GSM) Development Board",                   "iPhone5,1",   "n41dev")),
        ((0x02, 0x8950), ("iPhone 5 (Global)",                                  "iPhone5,2",   "n42ap")),
        ((0x03, 0x8950), ("iPhone 5 (Global) Development Board",                "iPhone5,2",   "n42dev")),
        ((0x0A, 0x8950), ("iPhone 5c (GSM)",                                    "iPhone5,3",   "n48ap")),
        ((0x0B, 0x8950), ("iPhone 5c (GSM) Development Board",                  "iPhone5,3",   "n48dev")),
        ((0x0E, 0x8950), ("iPhone 5c (Global)",                                 "iPhone5,4",   "n49ap")),
        ((0x0F, 0x8950), ("iPhone 5c (Global) Development Board",               "iPhone5,4",   "n49dev")),
        ((0x02, 0x8900), ("iPod touch (1st gen)",                               "iPod1,1",     "n45ap")),
        ((0x03, 0x8900), ("iPod touch (1st gen) Development Board",             "iPod1,1",     "n45dev")),
        ((0x00, 0x8720), ("iPod touch (2nd gen)",                               "iPod2,1",     "n72ap")),
        ((0x01, 0x8720), ("iPod touch (2nd gen) Development Board",             "iPod2,1",     "n72dev")),
        ((0x02, 0x8922), ("iPod touch (3rd gen)",                               "iPod3,1",     "n18ap")),
        ((0x03, 0x8922), ("iPod touch (3rd gen) Development Board",             "iPod3,1",     "n18dev")),
        ((0x08, 0x8930), ("iPod touch (4th gen)",                               "iPod4,1",     "n81ap")),
        ((0x09, 0x8930), ("iPod touch (4th gen) Development Board",             "iPod4,1",     "n81dev")),
        ((0x00, 0x8942), ("iPod touch (5th gen)",                               "iPod5,1",     "n78ap")),
        ((0x01, 0x8942), ("iPod touch (5th gen) Development Board",             "iPod5,1",     "n78dev")),
        ((0x02, 0x8930), ("iPad",                                               "iPad1,1",     "k48ap")),
        ((0x03, 0x8930), ("iPad",                                               "iPad1,1",     "k48ap")),
        ((0x04, 0x8940), ("iPad 2 (WiFi)",                                      "iPad2,1",     "k93ap")),
        ((0x05, 0x8940), ("iPad 2 (WiFi) Development Board",                    "iPad2,1",     "k93dev")),
        ((0x06, 0x8940), ("iPad 2 (GSM)",                                       "iPad2,2",     "k94ap")),
        ((0x07, 0x8940), ("iPad 2 (GSM) Development Board",                     "iPad2,2",     "k94dev")),
        ((0x02, 0x8940), ("iPad 2 (CDMA)",                                      "iPad2,3",     "k95ap")),
        ((0x03, 0x8940), ("iPad 2 (CDMA) Development Board",                    "iPad2,3",     "k95dev")),
        ((0x06, 0x8942), ("iPad 2 (WiFi) R2 2012",                              "iPad2,4",     "k93aap")),
        ((0x07, 0x8942), ("iPad 2 (WiFi) R2 2012 Development Board",            "iPad2,4",     "k93adev")),
        ((0x0A, 0x8942), ("iPad mini (WiFi)",                                   "iPad2,5",     "p105ap")),
        ((0x0B, 0x8942), ("iPad mini (WiFi) Development Board",                 "iPad2,5",     "p105dev")),
        ((0x0C, 0x8942), ("iPad mini (GSM)",                                    "iPad2,6",     "p106ap")),
        ((0x0D, 0x8942), ("iPad mini (GSM) Development Board",                  "iPad2,6",     "p106dev")),
        ((0x0E, 0x8942), ("iPad mini (Global)",                                 "iPad2,7",     "p107ap")),
        ((0x0F, 0x8942), ("iPad mini (Global) Development Board",               "iPad2,7",     "p107dev")),
        ((0x00, 0x8945), ("iPad (3rd gen, WiFi)",                               "iPad3,1",     "j1ap")),
        ((0x00, 0x8945), ("iPad (3rd gen, WiFi) Development Board",             "iPad3,1",     "j1dev")),
        ((0x02, 0x8945), ("iPad (3rd gen, CDMA)",                               "iPad3,2",     "j2ap")),
        ((0x03, 0x8945), ("iPad (3rd gen, CDMA) Development Board",             "iPad3,2",     "j2dev")),
        ((0x04, 0x8945), ("iPad (3rd gen, GSM)",                                "iPad3,3",     "j2aap")),
        ((0x05, 0x8945), ("iPad (3rd gen, GSM) Development Board",              "iPad3,3",     "j2adev")),
        ((0x00, 0x8955), ("iPad (4th gen, WiFi)",                               "iPad3,4",     "p101ap")),
        ((0x01, 0x8955), ("iPad (4th gen, WiFi) Development Board",             "iPad3,4",     "p101dev")),
        ((0x02, 0x8955), ("iPad (4th gen, GSM)",                                "iPad3,5",     "p102ap")),
        ((0x03, 0x8955), ("iPad (4th gen, GSM) Development Board",              "iPad3,5",     "p102dev")),
        ((0x04, 0x8955), ("iPad (4th gen, Global)",                             "iPad3,6",     "p103ap")),
        ((0x05, 0x8955), ("iPad (4th gen, Global) Development Board",           "iPad3,6",     "p103dev")),
        ((0x10, 0x8930), ("Apple TV 2",                                         "AppleTV2,1",  "k66ap")),
        ((0x11, 0x8930), ("Apple TV 2 Development Board",                       "AppleTV2,1",  "k66dev")),
        ((0x08, 0x8942), ("Apple TV 3",                                         "AppleTV3,1",  "j33ap")),
        ((0x09, 0x8942), ("Apple TV 3 Development Board",                       "AppleTV3,1",  "j33dev")),
        ((0x00, 0x8947), ("Apple TV 3 (2013)",                                  "AppleTV3,2",  "j33iap")),
        ((0x01, 0x8947), ("Apple TV 3 (2013) Development Board",                "AppleTV3,2",  "j33idev")),
        ((0x00, 0x8747), ("Lightning Digital AV Adapter",                       "iAccy1,1",    "b137ap")),
        ((0x01, 0x8747), ("Lightning Digital AV Adapter Development Board",     "iAccy1,1",    "b137dev")),
        ((0x02, 0x8747), ("Lightning Digital VGA Adapter",                      "iAccy1,2",    "b165ap")),
        ((0x03, 0x8747), ("Lightning Digital VGA Adapter Development Board",    "iAccy1,2",    "b165dev")),
        ((0x06, 0x8720), ("S5L8720X \"RB\"",                                    "Unknown",     "s5l8720xrbap")),
        ((0x07, 0x8720), ("S5L8720X \"RB\" Development Board",                  "Unknown",     "s5l8720xrbdev")),
        ((0x1E, 0x8720), ("S5L8720X iFPGA",                                     "iFPGA",       "s5l8720xfpgaap")),
        ((0x1F, 0x8720), ("S5L8720X iFPGA Development Board",                   "iFPGA",       "s5l8720xfpgadev")),
        ((0x3E, 0x8747), ("S5L8747X iFPGA",                                     "iFPGA",       "s5l8747xfpgaap")),
        ((0x3F, 0x8747), ("S5L8747X iFPGA Development Board",                   "iFPGA",       "s5l8747xfpgadev")),
        ((0x3E, 0x8920), ("S5L8920X iFPGA",                                     "iFPGA",       "s5l8920xfpgaap")),
        ((0x3F, 0x8920), ("S5L8920X iFPGA Development Board",                   "iFPGA",       "s5l8920xfpgadev")),
        ((0x3E, 0x8922), ("S5L8922X iFPGA",                                     "iFPGA",       "s5l8922xfpgaap")),
        ((0x3F, 0x8922), ("S5L8922X iFPGA Development Board",                   "iFPGA",       "s5l8922xfpgadev")),
        ((0x1E, 0x8930), ("S5L8930X iFPGA",                                     "iFPGA",       "s5l8930xfpgaap")),
        ((0x1F, 0x8930), ("S5L8930X iFPGA Development Board",                   "iFPGA",       "s5l8930xfpgadev")),
        ((0x3E, 0x8940), ("S5L8940X iFPGA",                                     "iFPGA",       "s5l8940xfpgaap")),
        ((0x3F, 0x8940), ("S5L8940X iFPGA Development Board",                   "iFPGA",       "s5l8940xfpgadev")),
        ((0x3E, 0x8942), ("S5L8942X iFPGA",                                     "iFPGA",       "s5l8942xfpgaap")),
        ((0x3F, 0x8942), ("S5L8942X iFPGA Development Board",                   "iFPGA",       "s5l8942xfpgadev")),
        ((0x3E, 0x8945), ("S5L8945X iFPGA",                                     "iFPGA",       "s5l8945xfpgaap")),
        ((0x3F, 0x8945), ("S5L8945X iFPGA Development Board",                   "iFPGA",       "s5l8945xfpgadev")),
        ((0x3E, 0x8947), ("S5L8947X iFPGA",                                     "iFPGA",       "s5l8947xfpgaap")),
        ((0x3F, 0x8947), ("S5L8947X iFPGA Development Board",                   "iFPGA",       "s5l8947xfpgadev")),
        ((0x3C, 0x8950), ("Swifter",                                            "Unknown",     "swifterap")),
        ((0x3D, 0x8950), ("Swifter Development Board",                          "Unknown",     "swifterdev")),
        ((0x3E, 0x8950), ("S5L8950X iFPGA",                                     "iFPGA",       "s5l8950xfpgaap")),
        ((0x3F, 0x8950), ("S5L8950X iFPGA Development Board",                   "iFPGA",       "s5l8950xfpgadev")),
        ((0x3E, 0x8955), ("S5L8955X iFPGA",                                     "iFPGA",       "s5l8955xfpgaap")),
        ((0x3F, 0x8955), ("S5L8955X iFPGA Development Board",                   "iFPGA",       "s5l8955xfpgadev")),
    ].into_iter().collect();
}

#[derive(Default, Debug)]
pub struct DeviceInfo {
    pub ecid: Option<u64>,
    pub bdid: Option<Vec<u32>>,
    pub cpid: Option<u32>,
    pub sdom: Option<u32>,
    pub sepo: Option<u32>,
    pub cepo: Option<u32>,
    pub prod: Option<u32>,
    pub nonc: Option<[u8; 20]>,
    pub ovrd: Option<u32>,
}

impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ecid) = self.ecid {
            writeln!(f, " for the device with the following:\n\tECID: {ecid:X}")?;
        } else {
            writeln!(f, ", but unpersonalized with the following constraints:")?;
        };
        if let Some(chip) = &self.cpid {
            writeln!(f, "\tChip ID: 0x{chip:X}")?;
        }
        if let Some(board) = &self.bdid {
            let boards = board
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            write!(
                f,
                "\tBoard ID{}: {boards}",
                if boards.len() > 1 { "s" } else { "" },
            )?;
            if let Some(cpid) = self.cpid {
                write!(f, " (")?;
                let mut biter = board.iter().peekable();
                while let Some(i) = biter.next() {
                    write!(
                        f,
                        "{}",
                        BOARDMAP.get(&(*i, cpid)).map_or("Unknown device", |x| x.0)
                    )?;
                    if biter.peek().is_some() {
                        write!(f, ", ")?;
                    }
                }
                writeln!(f, ")")?;
            } else {
                writeln!(f)?;
            }
        }
        if let Some(sdom) = &self.sdom {
            let sdomtype = match sdom {
                0 => Cow::from("Manufacturer"),
                1 => Cow::from("Darwin"),
                3 => Cow::from("RTXC"),
                x => Cow::from(format!("Unknown Security Domain ({x})")),
            };
            writeln!(f, "\tSecurity Domain: 0x{sdom:X} ({sdomtype})",)?;
        }
        if let Some(sepo) = &self.sepo {
            writeln!(f, "\tSecurity Epoch: 0x{sepo:X}")?;
        }
        if let Some(cepo) = &self.cepo {
            writeln!(f, "\tHardware Epoch: 0x{cepo:X}")?;
        }
        if let Some(prod) = &self.prod {
            let prodmode = match prod {
                0 => "False",
                1 => "True",
                _ => "Unknown",
            };
            writeln!(f, "\tProduction Mode: {prodmode}")?;
        }
        if let Some(nonc) = &self.nonc {
            writeln!(
                f,
                "\tAP Nonce (ignored for local boot): {}",
                hex::encode_upper(nonc)
            )?;
        }
        if let Some(ovrd) = self.ovrd {
            writeln!(f, ", and applies the override: {}", override_types(ovrd))?;
        }
        Ok(())
    }
}
