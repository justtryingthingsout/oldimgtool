# oldimgtool
A img2/3 parser, made in rust

## Usage
```
oldimgtool [OPTIONS] <INPUT> [OUTPUT]

Arguments:
    <INPUT>     Input filename
    <OUTPUT>    Output filename

Options:
    -2                         (IMG2 only) Keep the IMG2 header, but remove the S5L header
    -a                         Output all info about the image
    -d                         Only decrypt, do not extract (overrides -e)
    -e                         Only extracts, do not decompress (only applies to kernel)
    -h, --help                 Print help information
        --iv <IV>              Specify iv for decryption
    -k, --key <KEY|IVKEY>      Specify key for decryption
    -m, --create <S5L|IMG3>    Create a image with a image type (setters will be used)
    -v, --verify               Verify the image
        --version              Print version information

Getters:
    -b               Output keybags
    -c <FILE>        Save the cert chain to a file
    -s <FILE>        Save the signature to a file
    -t               Output image type
        --ver        Print version in IMG3

Setters:
    -B                          Only set the keybag, do not encrypt
    -C <FILE>                   Set or replace the cert chain from a file
    -D <TYPE>                   Set or replace the data buffer from a file
    -K <IV> <KEY> <TYPE>        Set the keybag and encrypt data with it, type can be prod or dev
    -S <FILE>                   Set or replace the signature from a file
    -T <TYPE>                   Set or rename the image type (4cc)
    -V <VERSION>                Set the version string in IMG3
```

## Examples
Extracting a image:
`oldimgtool applelogo@2x~iphone.s5l8950x.img3 logo.bin`

Extracting a image using a decryption IV and keys:
`oldimgtool --iv e8744b87c6b4c134c00432a5b8af302b -k 7b2764a96f1ab43ebc73e2167c774cefaed671d5c4522bae12d7e0e9da3e7e3a iBoot.n94ap.RELEASE.img3 iboot.bin`

Extracting a image's keybags:
`oldimgtool -b iBoot.n94ap.RELEASE.img3`

Verifying a image's integrity and output the image's type
`oldimgtool -v -t iBoot.n94ap.RELEASE.img3`

## Building
First, install `cargo` if you haven't already, instructions are [here](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Then, run `cargo install`, and finally use it with `oldimgtool`.

## Credits
* iphone-dataprotection for the IMG3 SHSH verifier logic
* @pingw33n for the LZSS decoder made in Rust