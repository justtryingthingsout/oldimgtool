pub use {
    binrw::{
        binrw, 
        BinRead, 
        BinWrite,
        io::Cursor
    },
    openssl::{
        nid::Nid,
        x509::X509,
        string::OpensslString
    },
    std::{
        ops::Range,
        fs::write,
        str::from_utf8,
        borrow::Cow,
        fmt
    },
    crate::lzss::*,
    binrw::BinReaderExt,
    phf::phf_map, //static map because I know all the values
};

//utility macros

//cast to type, panicking if unable to do so
#[macro_export]
macro_rules! cast_force {
    ($e: expr, $t: ty) => {
        TryInto::<$t>::try_into($e).unwrap_or_else(|_| 
            panic!("Unable to cast to {}", stringify!($t))
        )
    }
}

//generate a struct from a slice of bytes, using binrw
#[macro_export]
macro_rules! cast_struct {
    ($t: ty, $arr: expr) => {
        Cursor::new($arr)
        .read_le::<$t>()
        .unwrap_or_else(|e| 
            panic!(
                "Unable to deserialize to {}, err: {e}, first 4 bytes: {bytes:x?}", 
                stringify!($t), 
                bytes=&$arr[0..4]
            )
        )
    }
}

//generate a struct from a slice of bytes with imported arguments, using binrw
#[macro_export]
macro_rules! cast_struct_args {
    ($t: ty, $arr: expr, $args: expr) => {
        <$t>::read_args(&mut Cursor::new($arr), $args)
        .unwrap_or_else(|e|
            panic!(
                "Unable to deserialize to {}, err: {e}, first 4 bytes: {bytes:x?}", 
                stringify!($t), 
                bytes=&$arr[0..4]
            )
        )
    }
}

//write a binrw struct to a mutable buffer
#[macro_export]
macro_rules! struct_write {
    ($str: expr, $arr: expr) => {
        $str
        .write(&mut Cursor::new(&mut $arr))
        .unwrap_or_else(|e| panic!("Unable to write to buffer: {e}"));
    }
}

//utility functions

//get the first common name in a X509Certificate
/// # Panics
/// Panics if the certificate has no common name
#[must_use] pub fn get_cn(cert: &X509) -> OpensslString {
    cert
    .subject_name()
    .entries_by_nid(Nid::COMMONNAME)
    .next()
    .and_then(|x| x.data().as_utf8().ok())
    .unwrap()
}

//write a buffer to a file with the specified path
/// # Panics
/// Panics if the file cannot be written into
pub fn write_file(path: &str, arr: &[u8]) {
    write(path, arr).unwrap_or_else(|e| panic!("Unable to write to \"{path}\": {e}"));
}

//create a range from the start and size
#[must_use] pub fn range_size(start: usize, size: usize) -> Range<usize> {
    start..start+size
}

//make a reversed string from bytes
/// # Panics
/// Panics if the bytes are not valid utf8
#[must_use] pub fn revstr_from_le_bytes(arr: &[u8]) -> String {
    from_utf8(arr).unwrap_or_else(|_| panic!("{:?}", arr)).chars().rev().collect::<String>()
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

//resize buffer and pad to a 4 byte boundary, deleting or inserting bytes as needed
pub fn do_resize(mainhead: &mut IMG3ObjHeader, head: &mut IMG3TagHeader, file: &mut Vec<u8>, off: usize, taglen: u32, newdat: Vec<u8>) {
    let oldbuflen = head.buf_len;
    let newbuflen = taglen;

    let newlen = newdat.len();
    head.buf = newdat;
    head.buf_len = taglen;

    match oldbuflen.cmp(&newbuflen) {
        std::cmp::Ordering::Greater => {
            file.drain(range_size(off + 12 + head.buf_len as usize, (oldbuflen - newbuflen) as usize));
        },
        std::cmp::Ordering::Less => {
            file.splice(range_size(off + 12 + oldbuflen as usize, 0), vec![0; (newbuflen - oldbuflen) as usize]);
        },
        std::cmp::Ordering::Equal => {},
    }

    //fix padding
    let oldpadlen = head.pad.len();
    head.pad.resize(newlen % 4, 0); //needs to be on a 4 byte boundary
    let newpadlen = head.pad.len();
    match oldpadlen.cmp(&newpadlen) {
        std::cmp::Ordering::Greater => {
            file.drain(range_size(off //offset of tag
                                        + 12 //size of header
                                        + head.buf_len as usize //size of data
                                        + newpadlen //size of padding
                                        , oldpadlen - newpadlen //difference in padding size
                                      ));
        },
        std::cmp::Ordering::Less => {
            file.splice(range_size(off + 12 + oldpadlen, 0), vec![0; newpadlen - oldpadlen]);
        },
        std::cmp::Ordering::Equal => {},
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

pub const LZSS_MAGIC: [u8; 8] = *b"complzss";

pub const IMG3_TAG_ILLB: u32 = 0x69_6C_6C_62; // illb
pub const IMG3_TAG_IBOT: u32 = 0x69_62_6F_74; // ibot
pub const IMG3_TAG_IBEC: u32 = 0x69_62_65_63; // ibec
pub const IMG3_TAG_IBSS: u32 = 0x69_62_73_73; // ibss
pub const IMG3_TAG_LOGO: u32 = 0x6C_6F_67_6F; // logo
pub const IMG3_TAG_DTRE: u32 = 0x64_74_72_65; // dtre
pub const IMG3_TAG_RECM: u32 = 0x72_65_63_6D; // recm
pub const IMG3_TAG_NSRV: u32 = 0x6E_73_72_76; // nsrv
pub const IMG3_TAG_GLYC: u32 = 0x67_6C_79_43; // glyC
pub const IMG3_TAG_GLYP: u32 = 0x67_6C_79_50; // glyP
pub const IMG3_TAG_CHG0: u32 = 0x63_68_67_30; // chg0
pub const IMG3_TAG_CHG1: u32 = 0x63_68_67_31; // chg1
pub const IMG3_TAG_BAT0: u32 = 0x62_61_74_30; // bat0
pub const IMG3_TAG_BAT1: u32 = 0x62_61_74_31; // bat1
pub const IMG3_TAG_BATF: u32 = 0x62_61_74_46; // batF
pub const IMG3_TAG_KRNL: u32 = 0x6B_72_6E_6C; // krnl
pub const IMG3_TAG_RKRN: u32 = 0x72_6B_72_6E; // rkrn
pub const IMG3_TAG_RDTR: u32 = 0x72_64_74_72; // rdtr
pub const IMG3_TAG_RDSK: u32 = 0x72_64_73_6B; // rdsk
pub const IMG3_TAG_RLGO: u32 = 0x72_6C_67_6F; // rlgo

pub const IMG3_TAG_CERT: u32 = 0x63_65_72_74; // cert (special, in kSecOIDAPPLE_EXTENSION_APPLE_SIGNING)

#[allow(non_upper_case_globals)]
pub const kHFSPlusSigWord: &[u8; 2] = b"H+";
#[allow(non_upper_case_globals)]
pub const kHFSXSigWord: &[u8; 2] = b"HX";

/// # Panics
/// Panics if lzss failed to decompress 
#[must_use] pub fn checkvalid_decry(buf: &[u8], expected: u32, ext: bool) -> Option<Vec<u8>> {
    let iboottags = [
        IMG3_TAG_ILLB,
        IMG3_TAG_IBOT,
        IMG3_TAG_IBEC,
        IMG3_TAG_IBSS,
    ];
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
        expected == IMG3_TAG_RKRN) {
        println!("Found compressed kernelcache");
        if !ext {
            let lzsstr = cast_struct!(LZSSHead, buf);
            assert_eq!(&lzsstr.comp_data[0..4], b"\xFF\xCE\xFA\xED");
            return Some(decompress(&lzsstr.comp_data, lzsstr.decomp_len, lzsstr.adler32).unwrap_or_else(|| panic!("Adler32 mismatch when decompressing kernelcache")));
        }
    } else if (&buf[range_size(0x400, 2)] == kHFSPlusSigWord
            || &buf[range_size(0x400, 2)] == kHFSXSigWord)
            && expected == IMG3_TAG_RDSK {
        println!("Found ramdisk");
    } else if (&buf[range_size(0x200, 5)] == b"iBoot" 
            || &buf[range_size(0x200, 4)] == b"iBSS" 
            || &buf[range_size(0x200, 4)] == b"iBEC" 
            || &buf[range_size(0x200, 3)] == b"LLB")  
            && iboottags.contains(&expected) {
        println!("Found iBoot");
    } else if &buf[0..7] == b"iBootIm" && imagetags.contains(&expected) { //
        println!("Found iBoot image");
    } else if iboottags.contains(&expected) || imagetags.contains(&expected) {
        println!("The image may be decrypted with the wrong key. Saving the file anyways...");
    }
    None
}

#[must_use] pub fn format_type(value: u8) -> String {
    match value {
        1 => Cow::from("Boot encrypted with UID key"),
        2 => Cow::from("Boot plaintext"),
        3 => Cow::from("Encrypted with GID key"),
        4 => Cow::from("Plaintext"),
        _ => Cow::from(format!("Unknown Format ({value})"))
    }.to_string()
}

#[must_use] pub fn override_types(value: u32) -> String {
    if value & (1 << 0) != 0 {
        String::from("Production override")
    } else {
        String::from("No override")
    }
}

//pub const IMG2_OPT_SIGNATURE_TYPE_EXTERNAL:      u32 = 1<<0;
//pub const IMG2_OPT_SIGNATURE_TYPE_INTERNAL_SHA1: u32 = 1<<1;
//pub const IMG2_OPT_SIGNATURE_TYPE_INTERNAL_CRC:  u32 = 1<<2;
//pub const IMG2_OPT_TRUSTED_IMAGE:                u32 = 1<<8;
pub const IMG2_OPT_ENCRYPTED_IMAGE:              u32 = 1<<9;
//pub const IMG2_OPT_INSTALLED_WITH_SB:            u32 = 1<<24;
pub const IMG2_OPT_EXTENSION_PRESENT:            u32 = 1<<30;
//pub const IMG2_OPT_IMMUTABLE:                    u32 = 1<<31;

pub static OPTMAP: phf::Map<u32, &'static str> = phf_map! {
    0u32 => "External Signature",
    1u32 => "SHA1 in Signature Data",
    2u32 => "CRC32 in Signature Data",
    8u32 => "Trusted Image",
    9u32 => "Encrypted Image",
    24u32 => "Image with Secure Boot",
    30u32 => "With extension header",
    31u32 => "Immutable"
};

#[must_use] pub fn opts(val: u32) -> String {
    if val == 0 { return String::from("No Options") }
    OPTMAP
    .entries()
    .filter(|i| val & (1 << i.0) != 0)
    .map(|i| *i.1)
    .collect::<Vec<&str>>()
    .join(", ")
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct S5LHeader {
    pub platform:         [u8; 4],
    pub version:          [u8; 3],
    pub format:           u8,
    pub entry:            u32,
    pub size_of_data:     u32, 
    pub footer_sig_off:   u32,
    pub footer_cert_off:  u32,
    pub footer_cert_len:  u32,
    pub salt:             [u8; 0x20], 
    pub unknown2:         u16,
    pub epoch:            u16,
    pub header_signature: [u8; 0x10],
    pub unencrypted_sig:  [u8; 4],
    pub _pad:             [u8; 0x7B0],
}

impl fmt::Display for S5LHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "S5L Header:\
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
              \n\tHeader signature: {:02X?},\
              \n\tUnencryped signature: {:02X?}", 
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
              &self.unencrypted_sig
        )
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug)]
pub struct IMG2Header {
    pub magic:           [u8; 4],
    pub img_type:        [u8; 4],
    pub revision:        u16,
    pub sec_epoch:       u16,
    pub load_addr:       u32,
    pub data_size:       u32,
    pub decry_data_size: u32,
    pub alloc_size:      u32,
    pub opts:            u32,
    pub sig_data:        [u8; 0x40],
    pub extsize:         u32,
    pub header_crc32:    u32,
}

impl fmt::Display for IMG2Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IMG2 Header:\
                  \n\tMagic: {}\
                  \n\tImage type: {}\
                  \n\tRevision: {:#X}\
                  \n\tSecurity epoch: {:#X}\
                  \n\tLoad address: {:#X}\
                  \n\tData size: {:#X}\
                  \n\tDecrypted data size: {:#X}\
                  \n\tAllocated size: {:#X}\
                  \n\tOptions: {}\
                  \n\tSignature: {:02X?}\
                  \n\tExternal header size: {:#X}\
                  \n\tHeader CRC-32: {:#X}",
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
    pub check:      u32,        /* CRC-32 of the succeeding fields */
    pub next_size:  u32,        /* Size in bytes of the next extension */
    pub ext_type:   Img2HeaderExtensionType,
    pub opt:        u32,
    #[br(count = cur_size)]
    pub data:       Vec<u8>,    /* Extension data. */
}

impl fmt::Display for IMG2ExtHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IMG2 Extension Header:\
                  \n\tCheck: {:#X}\
                  \n\tNext size: {:#X}\
                  \n\tExtension type: {}\
                  \n\tOptions: {}\
                  \n\tData: {}",
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
    pub image_granule:  u32, // fundamental block size (bytes)
    pub image_offset:   u32, // image header offset within granule (image granules)
    pub boot_blocksize: u32, // size of the bootblock (image granules)
    pub image_avail:    u32, // total granules available for images
    pub nvram_granule:  u32, // size of NVRAM blocks (bytes)
    pub nvram_offset:   u32, // offset to first NVRAM block (nvram granules)
    flags: u32, // flags field reserved for future use
    rsvd1: u32, // reserved 1 for future use
    rsvd2: u32, // reserved 2 for future use
    rsvd3: u32, // reserved 3 for future use
    rsvd4: u32, // reserved 4 for future use
    pub check: u32, // CRC-32 of header fields preceding this one
}

pub const S5L8702_HEADER_MAGIC: [u8; 4] = *b"8702";
pub const S5L8720_HEADER_MAGIC: [u8; 4] = *b"8720";
pub const S5L8730_HEADER_MAGIC: [u8; 4] = *b"8730";
pub const S5L8740_HEADER_MAGIC: [u8; 4] = *b"8740";
pub const S5L8900_HEADER_MAGIC: [u8; 4] = *b"8900";
pub const IMG2_SB_HEADER_CIGAM: [u8; 4] = *b"2GMI";
pub const IMG2_HEADER_CIGAM:    [u8; 4] = *b"2gmI";
pub const IMG3_HEADER_CIGAM:    [u8; 4] = *b"3gmI";

pub const SIGNED_ENCRYPT:         u8 = 1;
pub const SIGNED:                 u8 = 2;
pub const X509_SIGNED_ENCRYPTED:  u8 = 3;
pub const X509_SIGNED:            u8 = 4;

pub const IMG1_FORMAT_1: [u8; 3] = *b"1.0";
pub const IMG1_FORMAT_2: [u8; 3] = *b"2.0";

pub const IMG3_GAT_DATA:              [u8; 4]    = *b"ATAD";
pub const IMG3_GAT_SIGNED_HASH:       [u8; 4]    = *b"HSHS";
pub const IMG3_GAT_CERTIFICATE_CHAIN: [u8; 4]    = *b"TREC";
pub const IMG3_GAT_VERSION:           [u8; 4]    = *b"SREV";
//pub const IMG3_GAT_SECURITY_EPOCH:    [u8; 4]    = *b"OPES";
//pub const IMG3_GAT_SECURITY_DOMAIN:   [u8; 4]    = *b"MODS";
//pub const IMG3_GAT_PRODUCTION_STATUS: [u8; 4]    = *b"DORP";
//pub const IMG3_GAT_CHIP_TYPE:         [u8; 4]    = *b"PIHC";
//pub const IMG3_GAT_BOARD_TYPE:        [u8; 4]    = *b"DROB";
//pub const IMG3_GAT_UNIQUE_ID:         [u8; 4]    = *b"DICE";
//pub const IMG3_GAT_RANDOM_PAD:        [u8; 4]    = *b"TLAS";
pub const IMG3_GAT_TYPE:              [u8; 4]    = *b"EPYT";
//pub const IMG3_GAT_OVERRIDE:          [u8; 4]    = *b"DRVO";
//pub const IMG3_GAT_HARDWARE_EPOCH:    [u8; 4]    = *b"OPEC";
//pub const IMG3_GAT_NONCE:             [u8; 4]    = *b"CNON";
pub const IMG3_GAT_KEYBAG:            [u8; 4]    = *b"GABK";

pub const IMG3_TAG_DATA:              &str    = "DATA";
pub const IMG3_TAG_SIGNED_HASH:       &str    = "SHSH";
pub const IMG3_TAG_CERTIFICATE_CHAIN: &str    = "CERT";
pub const IMG3_TAG_VERSION:           &str    = "VERS";
pub const IMG3_TAG_SECURITY_EPOCH:    &str    = "SEPO";
pub const IMG3_TAG_SECURITY_DOMAIN:   &str    = "SDOM";
pub const IMG3_TAG_PRODUCTION_STATUS: &str    = "PROD";
pub const IMG3_TAG_CHIP_TYPE:         &str    = "CHIP";
pub const IMG3_TAG_BOARD_TYPE:        &str    = "BORD";
pub const IMG3_TAG_UNIQUE_ID:         &str    = "ECID";
pub const IMG3_TAG_RANDOM_PAD:        &str    = "SALT";
pub const IMG3_TAG_TYPE:              &str    = "TYPE";
pub const IMG3_TAG_OVERRIDE:          &str    = "OVRD";
pub const IMG3_TAG_HARDWARE_EPOCH:    &str    = "CEPO";
pub const IMG3_TAG_NONCE:             &str    = "NONC";
pub const IMG3_TAG_KEYBAG:            &str    = "KBAG";

//pub const APPLE_CERT_SHA512: &str = "5621f576006af21c100ab091653762ccc72e66caadb5b61235ef2d91595cbcf897c449353e9ce818c97ab2a8ee938c7204ea38887cb4eb8e8cff3234edbcc65b";

#[allow(non_upper_case_globals)]
pub const KEY_0x837: &[u8; 16] = b"\x18\x84\x58\xA6\xD1\x50\x34\xDF\xE3\x86\xF2\x3B\x61\xD4\x37\x74";

#[binrw]
#[brw(little)]
#[derive(Debug)]
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
        write!(f, 
            "IMG3 Object Header:\
              \n\tMagic: {},\
              \n\tSkip Distance: {:#x},\
              \n\tBuffer length: {:#x},\
              \n\tSigned length: {:#x},\
              \n\tType: {}", 
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
#[derive(Debug, Clone)]
pub struct IMG3TagHeader {
    pub tag: [u8; 4],
    pub skip_dist: u32,
    pub buf_len: u32,
    #[br(count = buf_len)]
    pub buf: Vec<u8>,
    #[br(count = skip_dist - buf_len - 12)]
    pub pad: Vec<u8>
}

fn tagtype(tag: [u8; 4]) -> Cow<'static, str>{
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
        "TYPE" => Cow::from("Type"),
        "OVRD" => Cow::from("Override"),
        "CEPO" => Cow::from("Hardware Epoch"),
        "NONC" => Cow::from("Nonce"),
        "KBAG" => Cow::from("Keybag"),
        x => Cow::from(format!("Unknown Tag {x:?}"))
    }
}

impl fmt::Display for IMG3TagHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, 
            "IMG3 Tag:\
            \n\tTag: {} ({}),\
            \n\tSkip Distance: {:#x},\
            \n\tBuffer length: {:#x},",
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
pub struct IMG3TagString{
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
    pub iv_bytes: [u8; 16],
    pub key_bytes: [u8; 32]
}

#[binrw]
#[brw(big)]
#[derive(Debug)]
pub struct LZSSHead {
    pub magic: [u8; 8],
    pub adler32: u32,
    pub decomp_len: u32,
    pub comp_len: u32,
    pub unk: u32,
    #[br(count = 360)]
    pub pad: Vec<u8>,
    #[br(count = comp_len)]
    pub comp_data: Vec<u8>
}

#[derive(Default, Debug)]
pub struct DeviceInfo {
    pub ecid: Option<u64>,
    pub bdid: Option<Vec<u32>>,
    pub cpid: Option<u32>,
    pub sdom: Option<u32>,
    pub sepo: Option<u32>,
    pub cepo: Option<u32>,
    pub prod: Option<u32>
}