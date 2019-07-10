extern crate cfg_if;
extern crate digest;
#[macro_use]
extern crate clap;
extern crate hash_functions;


use clap::Arg;
use std::{fs, io};

use hash_functions::{
    adler32, blake2b, blake2s, cksum, crc32, crc32c, fletcher16, fnv32, fnv32a, fnv32z, fnv64,
    fnv64a, fnv64z, groestl224, groestl256, groestl384, groestl512, md5, ripemd160, ripemd320,
    sha1, sha256, sha512, sum, sum_s, whirlpool,
};

macro_rules! help_line {
    ($e:expr) => {
        format!("        --{0:<11}Calculate {0:}\n", $e)
    };
    ($e:expr, $f:expr) => {
        format!("        --{0:<11}Calculate {0:}\t\t{1:}\n", $e, $f)
    };
}

fn main() -> Result<(), io::Error> {
    let mut app = app_from_crate!()
        .about("calculates hash from given file with given algorithm")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required_unless("stdin")
                .conflicts_with("stdin")
                .index(1),
        )
        .arg(
            Arg::with_name("stdin")
                .short("-i")
                .long("--stdin")
                .help("Use stdin instead of file"),
        );

    if let Some(x) = std::env::args().next() {
        let bin_name = std::path::Path::new(&x)
            .file_name()
            .expect("first arg is the binary name");
        app = app.bin_name(bin_name.to_str().expect("binary name should be utf-8"));
    };

    let mut help_template = String::from(
        r#"{bin} {version}
{about}

USAGE:
"#,
    );
    let usage_help = format!(
        "    {0} [FLAGS] [ALGORITHMS] INPUT
    or
    echo example | {0} [FLAGS] [ALGORITHMS] --stdin",
        app.get_bin_name().unwrap_or("{bin}")
    );
    help_template.push_str(&usage_help);
    help_template.push_str(
        r#"

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -i, --stdin      Use stdin instead of file

ALGORITHMS: [default: sha256]
"#,
    );
    let mut methods = vec![];

    if cfg!(feature = "blake2") {
        methods.push(Arg::with_name("blake2b").long("blake2b").group("mode"));
        methods.push(Arg::with_name("blake2s").long("blake2s").group("mode"));
        help_template.push_str(&help_line!("blake2b"));
        help_template.push_str(&help_line!("blake2s"));
    }
    if cfg!(feature = "md-5") {
        methods.push(Arg::with_name("md5").long("md5").group("mode"));
        help_template.push_str(&help_line!("md5"));
    }
    if cfg!(feature = "sha-1") {
        methods.push(Arg::with_name("sha1").long("sha1").group("mode"));
        help_template.push_str(&help_line!("sha1"));
    }
    if cfg!(feature = "sha2") {
        methods.push(
            Arg::with_name("sha256")
                .long("sha256")
                .visible_alias("sha2")
                .group("mode"),
        );
        methods.push(Arg::with_name("sha512").long("sha512").group("mode"));
        help_template.push_str(&help_line!("sha2", "[ same as sha256 ]"));
        help_template.push_str(&help_line!("sha256"));
        help_template.push_str(&help_line!("sha512"));
    }
    if cfg!(feature = "sha3") {
        methods.push(
            Arg::with_name("sha3_256")
                .long("sha3_256")
                .visible_alias("sha3")
                .group("mode"),
        );
        methods.push(Arg::with_name("sha3_512").long("sha3_512").group("mode"));
        help_template.push_str(&help_line!("sha3", "[ same as sha3_256 ]"));
        help_template.push_str(&help_line!("sha3_256"));
        help_template.push_str(&help_line!("sha3_512"));
    }
    if cfg!(feature = "whirlpool") {
        methods.push(Arg::with_name("whirlpool").long("whirlpool").group("mode"));
        help_template.push_str(&help_line!("whirlpool"));
    }

    if cfg!(feature = "ripemd160") {
        methods.push(Arg::with_name("ripemd160").long("ripemd160").group("mode"));
        help_template.push_str(&help_line!("ripemd160"));
    }

    if cfg!(feature = "ripemd320") {
        methods.push(Arg::with_name("ripemd320").long("ripemd320").group("mode"));
        help_template.push_str(&help_line!("ripemd320"));
    }

    if cfg!(feature = "groestl") {
        for item in ["groestl224", "groestl256", "groestl384", "groestl512"].iter() {
            methods.push(Arg::with_name(item).long(item).group("mode"));
            help_template.push_str(&help_line!(item));
        }
    }

    if cfg!(feature = "pruefung") {
        for item in [
            "adler32",
            "sum",
            "sum_s",
            "cksum",
            "fnv32",
            "fnv32a",
            "fnv32z",
            "fnv64",
            "fnv64a",
            "fnv64z",
            "fletcher16",
            "crc32",
            "crc32c",
        ]
        .iter()
        {
            methods.push(Arg::with_name(item).long(item).group("mode"));
            help_template.push_str(&help_line!(item));
        }
    }

    help_template.push_str(
        r#"
ARGS:
{positionals}"#,
    );

    app = app.args(&methods);
    app = app.template(&*help_template);

    let matches = app.get_matches();

    let mut file: Box<io::Read> = match matches.value_of("INPUT") {
        Some(x) => Box::new(fs::File::open(&x)?),
        None => Box::new(std::io::stdin()),
    };

    let mut hash = String::new();
    for method in matches.args.keys() {
        let hash_func = match *method {
            "sha256" => sha256,
            "sha512" => sha512,
            "sha1" => sha1,
            "blake2b" => blake2b,
            "blake2s" => blake2s,
            "md5" => md5,
            "ripemd160" => ripemd160,
            "ripemd320" => ripemd320,
            "whirlpool" => whirlpool,
            "groestl224" => groestl224,
            "groestl256" => groestl256,
            "groestl384" => groestl384,
            "groestl512" => groestl512,
            "crc32" => crc32,
            "crc32c" => crc32c,
            "adler32" => adler32,
            "sum" => sum,
            "sum_s" => sum_s,
            "cksum" => cksum,
            "fnv32" => fnv32,
            "fnv32a" => fnv32a,
            "fnv32z" => fnv32z,
            "fnv64" => fnv64,
            "fnv64a" => fnv64a,
            "fnv64z" => fnv64z,
            "fletcher16" => fletcher16,
            _ => continue,
        };
        hash = hash_func(&mut file);
        break;
    }

    println!("{}", hash);
    Ok(())
}
