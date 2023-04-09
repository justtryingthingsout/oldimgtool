use crate::{
    img2,
    img3,
    utils::*,
    Args
};

use colored::Colorize;
use crc32fast::hash;

/// # Panics
/// Panics if the buffer does not contain a valid IMG1/S5L file, or the arguments are incorrect.
pub fn parse(file: &[u8], args: &Args) {
    let head = cast_struct!(IMG2Superblock, &file[0x8400..]);
    if args.all {
        println!("IMG2 Superblock Header: \
                  \n\t Magic: {}\
                  \n\t Image Granule size: {:#X}\
                  \n\t Image Header offset: {:#X}\
                  \n\t Boot Blocksize: {:#X}\
                  \n\t Total Granules: {:#X}\
                  \n\t NVRAM Granules: {:#X}\
                  \n\t NVRAM Offset: {:#X}\
                  \n\t CRC32 Of Header: {:#X}",
                    revstr_from_le_bytes(&head.magic),
                    head.image_granule,
                    head.image_offset,
                    head.boot_blocksize,
                    head.image_avail,
                    head.nvram_granule,
                    head.nvram_offset,
                    head.check
        );
    }
    if args.verify {
        println!("Superblock Header CRC32 is {}", 
                if hash(&file[0x8400..0x8430]) == head.check {
                    "correct".green()
                } else {
                    "incorrect".red()
                }
        );
    }
    let mut dirpath = None;
    if let Some(ref out) = args.outfile {
        dirpath = Some(std::path::PathBuf::from(out));
        if !dirpath.as_ref().unwrap().is_dir() {
            println!("Please specify a output directory to store the extracted files to.");
            return;
        }
    }
    let mut i = ((head.image_offset + head.boot_blocksize) * head.image_granule) as usize;
    let mut global_valid = true;
    while i < file.len() {
        let mut to_add = 0;
        let mut is_valid = true;
        if file[i..i+4] == IMG2_HEADER_CIGAM {
            let img2head = cast_struct!(IMG2Header, &file[i..]);
            let filelen = 0x3E0 + img2head.decry_data_size;
            let mut newargs = args.clone();
            if let Some(ref path) = dirpath {
                let mut newpath = path.clone();
                newpath.push(format!("{}.img2", revstr_from_le_bytes(&img2head.img_type)));
                write_file(&newpath.to_string_lossy(), &file[range_size(i, filelen as usize)]);
            }
            newargs.outfile = None;
            img2::parse(&file[i..], &newargs, &mut is_valid, &None);
            println!("IMG2 file of type \"{}\" is {}", 
                revstr_from_le_bytes(&img2head.img_type),
                if is_valid {
                    "valid".green()
                } else {
                    global_valid = false;
                    "invalid".red()
                }
            );
            to_add = (cast_force!(filelen, isize) + cast_force!(head.image_granule - 1, isize)) & -cast_force!(head.image_granule, isize);
        } else if file[i..i+4] == IMG3_HEADER_CIGAM {
            let img3head = cast_struct!(IMG3ObjHeader, &file[i..]);
            let mut newargs = args.clone();
            if let Some(ref path) = dirpath {
                let mut newpath = path.clone();
                newpath.push(format!("{}.img3", from_utf8(&img3head.img3_type.to_be_bytes()).unwrap()));
                write_file(&newpath.to_string_lossy(), &file[range_size(i, img3head.skip_dist as usize)]);
            }
            newargs.outfile = None;
            let mut devinfo = None;
            img3::parse(file[range_size(i, img3head.skip_dist as usize)].to_owned(), &mut newargs, &mut is_valid, &mut devinfo);
            println!("IMG3 file of type \"{}\" is {}", 
                from_utf8(&img3head.img3_type.to_be_bytes()).unwrap(),
                if is_valid {
                    "valid".green()
                } else {
                    global_valid = false;
                    "invalid".red()
                }
            );
            to_add = (cast_force!(img3head.skip_dist, isize) + cast_force!(head.image_granule - 1, isize)) 
                     & -cast_force!(head.image_granule, isize);
        }
        i += head.image_granule as usize + cast_force!(to_add, usize);
    }
    println!("This bootchain is {}", 
                if global_valid {
                    "valid".green()
                } else {
                    "invalid".red()
                }
    );
}