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
    clap::Parser,
    colored::Colorize,
    oldimgtool::{img1, img2, img3, superblock, utils::*, Args},
    std::fs,
};

fn main() {
    let mut args = Args::parse();

    let mut is_valid = true;
    let fw: Vec<u8> =
        fs::read(&args.filename).unwrap_or_else(|e| panic!("Cannot read image, error: {e}"));
    if let Some(create) = &args.create {
        if args.outfile.is_some() {
            match create.as_str() {
                "S5L" => img1::create(&fw, &args),
                "IMG3" => img3::create(fw, &args),
                x => panic!("Invalid image type: {x}"),
            }
        } else {
            panic!("No output file specified");
        }
    } else {
        let key = args.key.as_ref().and_then(|k| hex::decode(k).ok());
        match fw[..4].try_into().unwrap() {
            ref x if IMG1_PLATFORMS.contains(x) =>
            // Platform as magic
            {
                img1::parse(&fw, &args)
            }
            IMG2_HEADER_CIGAM => {
                img2::parse(&fw, &args, &mut is_valid, &key); //Img2 in le
                if args.verify {
                    println!(
                        "This image is {}",
                        if is_valid {
                            "valid".green()
                        } else {
                            "invalid".red()
                        }
                    );
                }
            }
            IMG3_HEADER_CIGAM => {
                //Img3 in le
                let mut devinfo = None;
                let _ = img3::parse(fw, &mut args, &mut is_valid, &mut devinfo);
            }
            IMG2_SB_HEADER_CIGAM => {
                //IMG2 in le
                superblock::parse(fw, &mut args);
            }
            x => panic!(
                "Unknown image type with magic: {}",
                if x.iter().all(|x| x.is_ascii()) {
                    format!("\"{}\"", std::str::from_utf8(&x).unwrap())
                } else {
                    format!("{x:02x?}")
                }
            ),
        }
    };
}
