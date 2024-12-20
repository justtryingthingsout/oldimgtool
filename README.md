# oldimgtool
A IMG1/2/3 parser and a NOR dump parser, made in Rust

## Usage
```
oldimgtool [OPTIONS] <INPUT> [OUTPUT]

Arguments:
  <INPUT>   Input filename
  [OUTPUT]  Output filename

Options:
  -v, --verify             Verify the image
      --iv <IV>            Specify iv for decryption
  -k, --key <KEY|IVKEY>    Specify key for decryption
  -e                       Only extracts, do not decompress (only applies to kernel)
      --comp               Compress the data before saving (use with -D)
  -d                       Only decrypt, do not extract (overrides -e)
  -2                       Keep the IMG2 header, but remove the IMG1 header (IMG1 only)
  -m, --create <S5L|IMG3>  Create a image with a image type (setters will be used)
  -h, --help               Print help

Getters:
  -a             Output all info about the image
      --ver      Print version (IMG2/IMG3)
  -b             Output keybags (IMG3 only)
  -t             Output image type (IMG2/IMG3)
  -s <FILE>      Save the signature to a file (IMG1/IMG3)
  -c <FILE>      Save the cert chain to a file (IMG1/IMG3)

Setters:
  -V <VERSION>              Set the version string
  -K <IV> <KEY> <TYPE>      Set the keybag and encrypt data with it, type can be prod or dev (IMG3 only)
      --no-crypt            Only set the keybag, do not encrypt (IMG3 only)
  -T <TYPE>                 Set or rename the image type (4cc)
  -D <FILE>                 Set or replace the data buffer from a file.
                            (Note: do not use this argument when creating a file, instead put the data in as the input file)
  -S <FILE>                 Set or replace the signature from a file
  -C <FILE>                 Set or replace the cert chain from a file
  -B <FILE>                 Personalize with/stitch a SHSH blob to the IMG3 file
```

## Examples
Extracting a image:  
`oldimgtool applelogo@2x~iphone.s5l8950x.img3 logo.bin`

Extracting a image using decryption IV and keys:  
`oldimgtool --iv e8744b87c6b4c134c00432a5b8af302b -k 7b2764a96f1ab43ebc73e2167c774cefaed671d5c4522bae12d7e0e9da3e7e3a iBoot.n94ap.RELEASE.img3 iBoot.bin`

Extracting a image's keybags:  
`oldimgtool -b iBoot.n94ap.RELEASE.img3`

Output the image's type:  
`oldimgtool -t iBoot.n94ap.RELEASE.img3`

Personalizing (signing) a image using a SHSH blob and verifying the now signed image's integrity:
`oldimgtool -B 10.3.4-n41.shsh2 -v iBSS.iphone5.RELEASE.dfu iBSS-signed.img3`

## Building
First, install `cargo` if you haven't already, instructions are [here](https://doc.rust-lang.org/cargo/getting-started/installation.html).

Then, run `cargo install --git https://github.com/justtryingthingsout/oldimgtool.git`.

Finally, use it with `oldimgtool`.

### Note for Windows
In order to get the program to compile, you may need to:
* Install LLVM as shown [here](https://rust-lang.github.io/rust-bindgen/requirements.html#windows)
* Install a OpenSSL binary from [here](https://wiki.openssl.org/index.php/Binaries)
* Point the OpenSSL installation path to the environmental variable `OPENSSL_DIR` if the installer didn't already

## Credits
* iphone-dataprotection for the IMG3 SHSH verifier logic
* freemyipod for information about the IMG1 structure