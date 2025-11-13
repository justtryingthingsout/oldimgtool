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

use {
    crate::{
        apticket, img2, img3,
        utils::{
            from_utf8, range_size, revstr_from_le_bytes, write_file, BinReaderExt, Cow, Cursor,
            IMG2Header, IMG2Superblock, IMG3ObjHeader, IMG2_HEADER_CIGAM, IMG3_HEADER_CIGAM,
            IMG3_TAG_SCAB,
        },
        Args,
    },
    binrw::BinWrite,
    colored::Colorize,
    crc32fast::hash,
    std::{cmp::min, fs::create_dir_all},
};

/// # Panics
/// Panics if the buffer does not contain a valid NOR file, or the arguments are
/// incorrect.
#[expect(clippy::too_many_lines)]
pub fn parse(mut file: Vec<u8>, args: &mut Args) {
    let head = cast_struct!(IMG2Superblock, &file);
    if args.all {
        eprintln!("{head}");
    }
    if args.verify {
        eprintln!(
            "Superblock Header CRC32 is {}\n",
            if hash(&file[0x0..0x30]) == head.check {
                "correct".green()
            } else {
                "incorrect".red()
            }
        );
    }
    let mut dirpath = None;
    if let Some(ref out) = args.outfile {
        dirpath = Some(out.path().to_path_buf());
        let tmp = dirpath.as_ref().unwrap();
        if out.is_std() || (tmp.exists() && !tmp.is_dir()) {
            eprintln!("Please specify a valid output directory to store the extracted files to.");
            return;
        } else if !tmp.exists() {
            create_dir_all(tmp).expect("Could not create directory");
        }
    }
    let mut i = ((head.image_offset + head.boot_blocksize) * head.image_granule) as usize;
    let mut global_valid = true;
    let mut invalid = false; // for keeping track of invalid magics
    while i < min((head.image_avail * head.image_granule) as usize, file.len()) {
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
                    write_file(&newpath, &file[range_size(i, filelen as usize)]);
                }
                newargs.outfile = None;
                img2::parse(&file[i..], &mut newargs, &mut is_valid, &None);
                if args.verify {
                    eprintln!(
                        "IMG2 file of type \"{}\" is {}\n",
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
            }
            IMG3_HEADER_CIGAM => {
                let mut img3head = cast_struct!(IMG3ObjHeader, &file[i..]);
                let skipdist = cast_force!(img3head.skip_dist, usize);
                if img3head.skip_dist > img3head.buf_len + 0x14 + 0x8 {
                    img3head.skip_dist = img3head.buf_len + 0x14 + 0x8;
                    struct_write!(img3head, file[i..]);
                }
                if let Some(ref path) = dirpath {
                    let mut newpath = path.clone();
                    newpath.push(format!(
                        "{}.img3",
                        from_utf8(&img3head.img3_type.to_be_bytes()).unwrap()
                    ));
                    write_file(
                        &newpath,
                        // apple might have messed up and forgot to account for the entirety of the
                        // image size, so add +4 here
                        &file[range_size(i, img3head.skip_dist as usize + 4)],
                    );
                }
                args.outfile = None;
                let mut devinfo = None;
                let apticket = img3::parse(file[i..].to_owned(), args, &mut is_valid, &mut devinfo);
                if img3head.img3_type == IMG3_TAG_SCAB && args.verify {
                    eprintln!("SCAB IMG3 found, validating as APTicket...");
                    let validticket = apticket::validate(apticket.as_ref().unwrap());
                    if validticket {
                        args.apticketbuf = apticket;
                    } else {
                        eprintln!("Not parsing invalid APTicket.");
                    }
                    eprintln!();
                } else if args.verify {
                    eprintln!(
                        "IMG3 file of type \"{}\" is {}\n",
                        from_utf8(&img3head.img3_type.to_be_bytes()).unwrap(),
                        if is_valid {
                            "valid".green()
                        } else {
                            global_valid = false;
                            "invalid".red()
                        }
                    );
                }
                to_add = skipdist;
                invalid = false;
            }
            x => {
                if !invalid {
                    eprintln!(
                        "Found unknown image type with magic {}, ignoring\n",
                        if x.iter().all(|c| 31 < *c && *c < 127) {
                            Cow::from(std::str::from_utf8(&x).unwrap())
                        } else {
                            Cow::from(format!("{:02x?}", &x))
                        }
                    );
                    invalid = true;
                }
                to_add += 4; // just to keep it moving
            }
        }
        i += to_add;
    }
    if args.verify {
        eprintln!(
            "This bootchain is {}",
            if global_valid {
                "valid".green()
            } else {
                "invalid".red()
            }
        );
    }
}
