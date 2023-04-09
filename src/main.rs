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
        if let Some(op) = &args.outfile {
            let outpath = op.clone();
            match create.as_str() {
                "S5L"  => img1::create(&fw, &args, &outpath),
                "IMG3" => img3::create(fw, &args, &outpath),
                x => panic!("Invalid image type: {x}")
            }
        } else {
            panic!("No output file specified");
        }
    } else { 
        let key = match args.key {
            Some(ref k) => {hex::decode(k).ok()},
            None => None
        };
        if fw.len() > 0x8404 && fw[0x8400..0x8404] == IMG2_SB_HEADER_CIGAM {
            superblock::parse(&fw, &args); //IMG2
            return;
        };
        match fw[..4].try_into().unwrap() {
            S5L8702_HEADER_MAGIC |
            S5L8720_HEADER_MAGIC |
            S5L8730_HEADER_MAGIC |
            S5L8740_HEADER_MAGIC |
            S5L8900_HEADER_MAGIC => img1::parse(&fw, &args),              //8900 / 8970
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
