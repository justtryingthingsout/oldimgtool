//clippy config
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::too_many_lines,           // refactor required but not now
    clippy::struct_excessive_bools,   // arguments struct, can't change much
    clippy::wildcard_imports,         // this is only done for my own crates, others are specified
    clippy::too_many_arguments        // don't know what to do with the arguments, they are required
)]

use clap::Parser;

#[macro_use]
pub mod utils;
pub mod lzss;
pub mod img1;
pub mod img2;
pub mod img3;
pub mod superblock;

#[derive(Parser, Debug, Clone)]
#[clap(author="@plzdonthaxme", version="1.1", about="A IMG1/2/3 and NOR parser, made in Rust", disable_version_flag=true)]
pub struct Args {
    //main args
    #[clap(help="Input filename", value_name="INPUT")]
    pub filename: String,
    #[clap(help="Output filename", value_name="OUTPUT")]
    pub outfile: Option<String>,
    #[clap(short='v', long, help="Verify the image")]
    pub verify: bool,
    #[clap(long, help="Specify iv for decryption")]
    pub iv: Option<String>,
    #[clap(short, long, help="Specify key for decryption", value_name="KEY|IVKEY")]
    pub key: Option<String>,
    #[clap(short='e', help="Only extracts, do not decompress (only applies to kernel)")]
    pub ext: bool,
    #[clap(long="comp", help="Compress the data before saving (use with -D)")]
    pub comp: bool,
    #[clap(short='d', help="Only decrypt, do not extract (overrides -e)")]
    pub dec: bool,
    #[clap(short='2', help="Keep the IMG2 header, but remove the IMG1 header (IMG1 only)")]
    pub img2: bool,

    //getters
    #[clap(short, help="Output all info about the image")]
    pub all: bool,
    #[clap(long, help="Print version (IMG2/IMG3)", help_heading="GETTERS")]
    pub ver: bool,
    #[clap(short='b', help="Output keybags (IMG3 only)", help_heading="GETTERS")]
    pub keybags: bool,
    #[clap(short='t', help="Output image type (IMG2/IMG3)", help_heading="GETTERS")]
    pub imgtype: bool,
    #[clap(short='s', help="Save the signature to a file (IMG1/IMG3)", value_name="FILE", help_heading="GETTERS")]
    pub savesigpath: Option<String>,
    #[clap(short='c', help="Save the cert chain to a file (IMG1/IMG3)", value_name="FILE", help_heading="GETTERS")]
    pub savecertpath: Option<String>,

    //setters
    #[clap(short='V', help="Set the version string", value_name="VERSION", help_heading="SETTERS")]
    pub setver: Option<String>,
    #[clap(short='K', help="Set the keybag and encrypt data with it, type can be prod or dev (IMG3 only)", value_names = &["IV", "KEY", "TYPE"], help_heading="SETTERS")]
    pub setkbag: Option<Vec<String>>,
    #[clap(long="no-crypt", help="Only set the keybag, do not encrypt (IMG3 only)", help_heading="SETTERS")]
    pub onlykbag: bool,
    #[clap(short='T', help="Set or rename the image type (4cc)", value_name="TYPE", help_heading="SETTERS")]
    pub settype: Option<String>,
    #[clap(short='D', help="Set or replace the data buffer from a file. \n(Note: do not use this argument when creating a file, instead put the data in as the input file)", value_name="FILE", help_heading="SETTERS")]
    pub setdata: Option<String>,
    #[clap(short='S', help="Set or replace the signature from a file", value_name="FILE", help_heading="SETTERS")]
    pub sigpath: Option<String>,
    #[clap(short='C', help="Set or replace the cert chain from a file", value_name="FILE", help_heading="SETTERS")]
    pub certpath: Option<String>,
    #[clap(short='B', help="Personalize with/stitch a SHSH blob to the IMG3 file", value_name="FILE", help_heading="SETTERS")]
    pub shshpath: Option<String>,

    //create
    #[clap(short='m', long, help="Create a image with a image type (setters will be used)", value_name="S5L|IMG3")]
    pub create: Option<String>,
}