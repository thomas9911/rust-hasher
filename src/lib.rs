#[cfg(feature = "non-crypto")]
extern crate pruefung;

use cfg_if::cfg_if;

use digest::Digest;
use std::io;

#[cfg(feature = "non-crypto")]
use std::hash::Hasher;

#[cfg(feature = "gost94")]
use gost94::Digest as Gost94Digest;

fn do_hash<D, F>(mut d: D, f: &mut F) -> String
where
    D: digest::Digest + io::Write,
    <D as digest::Digest>::OutputSize: std::ops::Add,
    <<D as digest::Digest>::OutputSize as std::ops::Add>::Output:
        digest::generic_array::ArrayLength<u8>,
    F: io::Read,
{
    let _n = io::copy(f, &mut d).expect("copying in hasher went wrong");
    let hash = d.result();
    format!("{:x}", hash)
}

#[cfg(feature = "gost94")]
fn do_gost94_hash<D, F>(mut d: D, f: &mut F) -> String
where
    D: Gost94Digest,
    F: io::Read,
{
    const BUFFER_SIZE: usize = 1024;
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = match f.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => return format!("{}", e),
        };
        d.input(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    let hash = d.result();
    let mut out = String::new();
    for byte in hash {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

#[cfg(feature = "non-crypto")]
fn do_hash_with_hasher<D, F>(mut d: D, f: &mut F) -> String
where
    D: Hasher,
    F: io::Read,
{
    const BUFFER_SIZE: usize = 1024;
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = match f.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => return format!("{}", e),
        };
        d.write(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    let hash = d.finish();
    format!("{:x}", hash)
}

cfg_if! {
    if #[cfg(feature = "blake2")]{
        pub fn blake2s<F: io::Read>(f: &mut F) -> String{
            do_hash(blake2::Blake2s::new(), f)
        }
        pub fn blake2b<F: io::Read>(f: &mut F) -> String{
            do_hash(blake2::Blake2b::new(), f)
        }
    } else{
        pub fn blake2s<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with blake2")
        }
        pub fn blake2b<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with blake2")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "sha2")]{
        pub fn sha256<F: io::Read>(f: &mut F) -> String{
            do_hash(sha2::Sha256::new(), f)
        }
        pub fn sha512<F: io::Read>(f: &mut F) -> String{
            do_hash(sha2::Sha512::new(), f)
        }
    } else{
        pub fn sha256<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with sha2")
        }
        pub fn sha512<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with sha2")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "sha3")]{
        pub fn sha3_256<F: io::Read>(f: &mut F) -> String{
            do_hash(sha3::Sha3_256::new(), f)
        }
        pub fn sha3_512<F: io::Read>(f: &mut F) -> String{
            do_hash(sha3::Sha3_512::new(), f)
        }
    } else{
        pub fn sha3_256<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with sha3")
        }
        pub fn sha3_512<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with sha3")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "whirlpool")]{
        pub fn whirlpool<F: io::Read>(f: &mut F) -> String{
            do_hash(whirlpool::Whirlpool::new(), f)
        }
    } else{
        pub fn whirlpool<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with whirlpool")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "sha-1")]{
        pub fn sha1<F: io::Read>(f: &mut F) -> String{
            do_hash(sha1::Sha1::new(), f)
        }
    } else{
        pub fn sha1<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with sha-1")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "md-5")]{
        pub fn md5<F: io::Read>(f: &mut F) -> String{
            do_hash(md5::Md5::new() , f)
        }
    } else{
        pub fn md5<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with md-5")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "ripemd160")]{
        pub fn ripemd160<F: io::Read>(f: &mut F) -> String{
            do_hash(ripemd160::Ripemd160::new() , f)
        }
    } else{
        pub fn ripemd160<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with ripemd160")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "ripemd160")]{
        pub fn ripemd320<F: io::Read>(f: &mut F) -> String{
            do_hash(ripemd320::Ripemd320::new() , f)
        }
    } else{
        pub fn ripemd320<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with ripemd320")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "groestl")]{
        pub fn groestl224<F: io::Read>(f: &mut F) -> String{
            do_hash(groestl::Groestl224::default() , f)
        }
        pub fn groestl256<F: io::Read>(f: &mut F) -> String{
            do_hash(groestl::Groestl256::default() , f)
        }
        pub fn groestl384<F: io::Read>(f: &mut F) -> String{
            do_hash(groestl::Groestl384::default() , f)
        }
        pub fn groestl512<F: io::Read>(f: &mut F) -> String{
            do_hash(groestl::Groestl512::default() , f)
        }
    } else{
        pub fn groestl224<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with groestl")
        }
        pub fn groestl256<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with groestl")
        }
        pub fn groestl384<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with groestl")
        }
        pub fn groestl512<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with groestl")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "gost94")]{
        pub fn gost94pro<F: io::Read>(f: &mut F) -> String{
            do_gost94_hash(gost94::Gost94CryptoPro::default() , f)
        }
        pub fn gost94s2015<F: io::Read>(f: &mut F) -> String{
            do_gost94_hash(gost94::Gost94s2015::default() , f)
        }
        pub fn gost94test<F: io::Read>(f: &mut F) -> String{
            do_gost94_hash(gost94::Gost94Test::default() , f)
        }
    }
    else{
        pub fn gost94pro<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with gost94")
        }
        pub fn gost94s2015<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with gost94")
        }
        pub fn gost94test<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with gost94")
        }
    }
}

cfg_if! {
    if #[cfg(feature = "non-crypto")]{
        pub fn crc32<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::crc::Crc32::default() , f)
        }
        pub fn crc32c<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::crc::Crc32c::default() , f)
        }
        pub fn adler32<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::adler32::Adler32::default() , f)
        }
        pub fn sum<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::bsd::Bsd::default() , f)
        }
        pub fn sum_s<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::sysv::SysV::default() , f)
        }
        pub fn cksum<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::unix::Unix::default() , f)
        }
        pub fn fnv32<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv32::Fnv32::default() , f)
        }
        pub fn fnv32a<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv32::Fnv32a::default() , f)
        }
        pub fn fnv32z<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv32::Fnv32z::default() , f)
        }
        pub fn fnv64<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv64::Fnv64::default() , f)
        }
        pub fn fnv64a<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv64::Fnv64a::default() , f)
        }
        pub fn fnv64z<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fnv::fnv64::Fnv64z::default() , f)
        }
        pub fn fletcher16<F: io::Read>(f: &mut F) -> String{
            do_hash_with_hasher(pruefung::fletcher16::Fletcher16::default() , f)
        }

    } else{
        pub fn crc32<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn crc32c<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn adler32<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn sum<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn sum_s<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn cksum<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv32<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv32a<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv32z<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv64<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv64a<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fnv64z<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
        pub fn fletcher16<F: io::Read>(_f: &mut F) -> String{
            String::from("not compiled with non-crypto")
        }
    }
}
