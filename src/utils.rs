//mostly just copied off from iBoot src

pub use binrw::{
    binrw, 
    BinRead, 
    BinWrite,
    io::Cursor
};

pub use openssl::{
    nid::Nid,
    x509::X509,
    string::OpensslString
};

pub use std::{
    ops::Range,
    fs::write,
    str::from_utf8
};

//utility macros

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
        .write_to(&mut Cursor::new(&mut $arr))
        .unwrap_or_else(|e| panic!("Unable to write to buffer: {e}"));
    }
}

//utility functions

//get the first common name in a X509Certificate
pub fn get_cn(cert: &X509) -> OpensslString {
    cert
    .subject_name()
    .entries_by_nid(Nid::COMMONNAME)
    .next()
    .and_then(|x| x.data().as_utf8().ok())
    .unwrap()
}

//write a buffer to a file with the specified path
pub fn write_file(path: &str, arr: &[u8]) {
    write(path, arr).unwrap_or_else(|e| panic!("Unable to write to \"{path}\": {e}"));
}

//create a range from the start and size
pub fn range_size(start: usize, size: usize) -> Range<usize> {
    start..start+size
}

//make a reversed string from bytes
pub fn revstr_from_le_bytes(arr: &[u8]) -> String {
    from_utf8(arr).unwrap().chars().rev().collect::<String>()
}

//resize buffer and pad to a 4 byte boundary, deleting or inserting bytes as needed
pub fn do_resize(head: &mut IMG3TagHeader, file: &mut Vec<u8>, off: usize, taglen: u32, pad: &[u8]) {
    let oldbuf = head.buf_len;
    head.buf.resize(taglen as usize, 0);
    head.buf_len = taglen;
    let newbuf = taglen;
    if oldbuf > newbuf {
        file.drain(range_size(off + 12 + head.buf_len as usize, (oldbuf - newbuf) as usize));
    } else if newbuf > oldbuf {
        file.splice(range_size(off + 12 + oldbuf as usize, 0), vec![0; (newbuf - oldbuf) as usize]);
    }

    //fix padding
    let oldpad = head.pad.len();
    head.pad.resize(pad.len() % 4, 0); //needs to be on a 4 byte boundary
    let newpad = head.pad.len();
    if oldpad > newpad {
        file.drain(range_size(off + 12 + head.buf_len as usize + newpad, (oldpad - newpad) as usize));
    } else if newbuf > oldbuf {
        file.splice(range_size(off + 12 + oldpad as usize, 0), vec![0; (newpad - oldpad) as usize]);
    }
    head.skip_dist = 12 + newbuf + newpad as u32 - 1;

    struct_write!(head, file[off..]);
}


#[binrw]
#[br(little)]
#[derive(Debug)]
pub struct S5LHeader {
    pub platform:            [u8; 4],
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
    pub _pad:             [u8; 0x7B0],
}

#[binrw]
#[br(little)]
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
    pub sig_data:        [u32; 0x10],
    pub extsize:         u32,
    pub header_crc32:    u32,
}

type Img2HeaderExtensionType = [u8; 4];

#[binrw]
#[br(little, import(cur_size: u32))]
#[derive(Default, Debug)]
pub struct IMG2ExtHeader {
	pub check:      u32,	    /* CRC-32 of the succeeding fields */
	pub next_size:  u32,	    /* Size in bytes of the next extension */
	pub ext_type:   Img2HeaderExtensionType,
	pub opt:        u32,
    #[br(count = cur_size)]
	pub data:       Vec<u8>,	/* Extension data. */
}

#[binrw]
#[br(little)]
#[derive(Default, Debug)]
pub struct IMG2Superblock {
	magic: u32,
	image_granule: u32,  /* fundamental block size (bytes) */
	image_offset: u32,   /* image header offset within granule (image granules) */
	boot_blocksize: u32, /* size of the bootblock (image granules) */
	image_avail: u32,    /* total granules available for images. */
	nvram_granule: u32,  /* size of NVRAM blocks (bytes) */
	nvram_offset: u32,   /* offset to first NVRAM block (nvram granules) */
	flags: u32, /* flags field reserved for future use */
	rsvd1: u32, /* reserved 1 for future use */
	rsvd2: u32, /* reserved 2 for future use */
	rsvd3: u32, /* reserved 3 for future use */
	rsvd4: u32, /* reserved 4 for future use */
	check: u32, /* CRC-32 of header fields preceding this one */
}

pub const S5L8720_HEADER_MAGIC: &[u8; 4] = b"8720";
pub const S5L8900_HEADER_MAGIC: &[u8; 4] = b"8900";
pub const IMG2_SB_HEADER_MAGIC:    &[u8; 4] = b"IMG2";
pub const IMG2_HEADER_CIGAM:    &[u8; 4] = b"2gmI";
pub const IMG3_HEADER_CIGAM:    &[u8; 4] = b"3gmI";

#[binrw]
#[br(little)]
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

#[binrw]
#[br(little)]
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

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
pub struct IMG3TagString{
	/* number of valid bytes in the buffer */
	pub str_len: u32,
    #[br(count(str_len))]
    #[br(map = |s: Vec<u8>| String::from_utf8(s).unwrap())]
    #[bw(map = String::as_bytes)]
	pub str_bytes: String,
}

#[binrw]
#[br(little)]
#[derive(Debug)]
pub struct IMG3KBAG {
	pub selector: u32,
	pub key_size: u32,
	pub iv_bytes: [u8; 16],
	pub key_bytes: [u8; 32]
}

#[binrw]
#[br(big)]
#[derive(Debug)]
pub struct LZSSHead {
	pub magic: [u8; 8],
	pub adler32: u32,
	pub decomp_len: u32,
	pub comp_len: u32,
    unk: u32,
    #[br(count = 360)]
    pad: Vec<u8>,
    #[br(count = comp_len)]
    pub comp_data: Vec<u8>
}