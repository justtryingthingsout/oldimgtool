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

use crate::{
    img2,
    img3,
    utils::*,
    Args
};

use colored::Colorize;
use crc32fast::hash;
use std::path::PathBuf;

/// # Panics
/// Panics if the buffer does not contain a valid NOR file, or the arguments are incorrect.
pub fn parse(file: &[u8], args: &Args) {
    let head = cast_struct!(IMG2Superblock, &file);
    if args.all {
        println!("{head}");
    }
    if args.verify {
        println!("Superblock Header CRC32 is {}", 
                if hash(&file[0x0..0x30]) == head.check {
                    "correct".green()
                } else {
                    "incorrect".red()
                }
        );
    }
    let mut dirpath = None;
    if let Some(ref out) = args.outfile {
        dirpath = Some(PathBuf::from(out));
        if !dirpath.as_ref().unwrap().is_dir() {
            eprintln!("Please specify a output directory to store the extracted files to.");
            return;
        }
    }
    let mut i = ((head.image_offset + head.boot_blocksize) * head.image_granule) as usize;
    let mut global_valid = true;
    let mut invalid = false; // for keeping track of invalid magics
    while i < (head.image_avail * head.image_granule) as usize {
        let mut to_add = 0;
        let mut is_valid = true; // for image verification
        match cast_force!(&file[range_size(i, 4)], [u8; 4]) {
            IMG2_HEADER_CIGAM => {
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
                if args.verify {
                    println!("IMG2 file of type \"{}\" is {}", 
                        revstr_from_le_bytes(&img2head.img_type),
                        if is_valid {
                            "valid".green()
                        } else {
                            global_valid = false;
                            "invalid".red()
                        }
                    );
                }
                to_add = cast_force!(filelen, usize);
                invalid = false;
            }, IMG3_HEADER_CIGAM => {
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
                if args.verify {
                    println!("IMG3 file of type \"{}\" is {}", 
                        from_utf8(&img3head.img3_type.to_be_bytes()).unwrap(),
                        if is_valid {
                            "valid".green()
                        } else {
                            global_valid = false;
                            "invalid".red()
                        }
                    );
                }
                to_add = cast_force!(img3head.skip_dist, usize);
                invalid = false;
            },
            x => {
                if !invalid {
                    eprintln!("Found unknown image type with magic {}, ignoring", if x.iter().all(|c| 31 < *c && *c < 127) {
                        Cow::from(std::str::from_utf8(&x).unwrap())
                    } else {
                        Cow::from(format!("{:02x?}", &x))
                    });
                    invalid = true;
                }
                to_add += 4; // just to keep it moving
            }
        }
        i += to_add;
    }
    if args.verify {
        println!("This bootchain is {}", 
                    if global_valid {
                        "valid".green()
                    } else {
                        "invalid".red()
                    }
        );
    }
}