extern crate cfg_if;
extern crate digest;
#[macro_use]
extern crate clap;
extern crate hash_functions;

use clap::Arg;

use std::str::FromStr;
use std::{fs, io};
use hash_functions::{
    adler32, blake2b, blake2s, cksum, crc32, crc32c, fletcher16, fnv32, fnv32a, fnv32z, fnv64,
    fnv64a, fnv64z, gost94pro, gost94s2015, gost94test, groestl224, groestl256, groestl384,
    groestl512, md5, ripemd160, ripemd320, sha1, sha256, sha3_256, sha3_512, sha512, sum, sum_s,
    whirlpool,
};

macro_rules! help_line {
    ($e:expr) => {
        format!("        --{0:<14}Calculate {0:}\n", $e)
    };
    ($e:expr, $f:expr) => {
        format!("        --{0:<14}Calculate {0:}\t\t{1:}\n", $e, $f)
    };
}

fn main() -> Result<(), io::Error> {
    let mut template = String::new();
    let app = gen_app(&mut template);
    let matches = app.get_matches();

    if matches.is_present("complete") {
        let shell = clap::Shell::from_str(matches.value_of("complete").unwrap()).unwrap();

        let mut new_template = String::new();
        let mut new_app = gen_app(&mut new_template);
        let bin_name = new_app.get_bin_name().unwrap_or(crate_name!()).to_string();
        new_app.gen_completions_to(bin_name, shell, &mut io::stdout());
        return Ok(());
    }

    let mut file: Box<io::Read> = match matches.value_of("INPUT") {
        Some(x) => Box::new(fs::File::open(&x)?),
        None => Box::new(std::io::stdin()),
    };

    let mut hash = String::from("no algorithm set");
    for method in matches.args.keys() {
        let hash_func = match *method {
            "sha256" => sha256,
            "sha512" => sha512,
            "sha3_256" => sha3_256,
            "sha3_512" => sha3_512,
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
            "gost94pro" => gost94pro,
            "gost94test" => gost94test,
            "gost94s2015" => gost94s2015,
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
    if !matches.is_present("no_default"){
        if &hash == "no algorithm set"{
            hash = sha256(&mut file)
        }
    }

    println!("{}", hash);
    Ok(())
}

fn gen_app<'a>(help_template: &'a mut String) -> clap::App<'a, 'a> {
    let mut app = app_from_crate!()
        .about("calculates hash from given file with given algorithm")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required_unless_one(&["stdin", "complete"])
                .conflicts_with("stdin")
                .index(1),
        )
        .arg(
            Arg::with_name("complete")
                .long("--complete")
                .takes_value(true)
                .possible_values(&clap::Shell::variants())
                .case_insensitive(true)
                .help("Generate completion script"),
        )
        .arg(
            Arg::with_name("no_default")
                .long("--no-default")
                .help("Do not set sha2 as default hasher"),
        )
        .arg(
            Arg::with_name("stdin")
                .short("-i")
                .long("--stdin")
                .conflicts_with("complete")
                .help("Use stdin instead of file"),
        );

    if let Some(x) = std::env::args().next() {
        let bin_name = std::path::Path::new(&x)
            .file_name()
            .expect("first arg is the binary name");
        app = app.bin_name(bin_name.to_str().expect("binary name should be utf-8"));
    };

    help_template.push_str(
        r#"{bin} v{version}
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
    -h, --help          Prints help information.
    -V, --version       Prints version information.
    -i, --stdin         Use stdin instead of file.
        --no-default    Do not set sha2 as default hasher.
        --complete      Generate completion scripts.
                        "#,
    );
    help_template.push_str(&format!("Possible values: {:?}", clap::Shell::variants()));
    help_template.push_str(
        r#"

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
    if cfg!(feature = "gost94") {
        methods.push(
            Arg::with_name("gost94pro")
                .long("gost94pro")
                .visible_alias("gost94")
                .group("mode"),
        );
        methods.push(
            Arg::with_name("gost94test")
                .long("gost94test")
                .group("mode"),
        );
        methods.push(
            Arg::with_name("gost94s2015")
                .long("gost94s2015")
                .group("mode"),
        );
        help_template.push_str(&help_line!("gost94", "[ same as gost94pro ]"));
        help_template.push_str(&help_line!("gost94pro"));
        help_template.push_str(&help_line!("gost94test"));
        help_template.push_str(&help_line!("gost94s2015"));
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
    app = app.template(&**help_template);
    app
}