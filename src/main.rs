use {
    oldimgtool::{
        Args,
        utils::*,
        img1,
        img2,
        img3,
        superblock
    },
    clap::Parser,
    std::fs,
    colored::Colorize,
};

fn main() {
    let mut args = Args::parse();

    let mut is_valid = true;
    let fw: Vec<u8> = fs::read(&args.filename).unwrap_or_else(|e| panic!("Cannot read image, error: {e}"));
    if let Some(create) = &args.create {
        if args.outfile.is_some() {
            match create.as_str() {
                "S5L"  => img1::create(&fw, &args),
                "IMG3" => img3::create(fw, &args),
                x => panic!("Invalid image type: {x}")
            }
        } else {
            panic!("No output file specified");
        }
    } else { 
        let key = args.key.as_ref().and_then(|k| hex::decode(k).ok());
        if fw.len() > 0x8404 && fw[0x8400..0x8404] == IMG2_SB_HEADER_CIGAM {
            superblock::parse(&fw, &args); //IMG2
            return;
        };
        match fw[..4].try_into().unwrap() {
            ref x if IMG1_PLATFORMS.contains(x) => // Platform as magic
                img1::parse(&fw, &args),
            IMG2_HEADER_CIGAM => {
                img2::parse(&fw, &args, &mut is_valid, &key); //Img2 in le
                if args.verify {
                    println!("This image is {}", 
                            if is_valid {
                                "valid".green()
                            } else {
                                "invalid".red()
                            }
                    );
                }
            },
            IMG3_HEADER_CIGAM => { //Img3 in le
                let mut devinfo = None;
                img3::parse(fw, &mut args, &mut is_valid, &mut devinfo)           
            },
            x => panic!("Unknown image type with magic: {x:02x?}")
        }
    };
}
