/// tests, crates, shared convenience types/aliases
extern crate argon2;
extern crate blake2_rfc;
extern crate chashmap;
extern crate memmap;
extern crate rayon;
extern crate rust_sodium;
extern crate tiny_keccak;

pub mod cipher;
pub mod crypt;
pub mod key_store;

use memmap::MmapMut as MmapMut;
use memmap::MmapOptions as MmapOptions;
use rust_sodium::crypto::stream::xchacha20 as xcc;
use rust_sodium::randombytes::randombytes as random;
use rust_sodium::utils::memcmp as memcmp;
use rust_sodium::utils::memzero as memzero;
use tiny_keccak::Keccak as Keccak;

pub type CryptKey = rust_sodium::crypto::stream::xchacha20::Key;
pub type CryptNon = rust_sodium::crypto::stream::xchacha20::Nonce;

pub struct Salt(pub [u8; 16]);
pub type AuthKey = Salt;

impl Salt {
    pub fn from_slice(raw: &[u8]) -> Option<Salt> {
        if raw.len() != 16 { return None }
        let mut k = [0u8; 16];

        (0..16).for_each(|i| {
            k[i]   = raw[i].clone();
        });

        Some(Salt(k))
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        let &mut Salt(ref mut v) = self;
        memzero(v);
    }
}

impl std::ops::Deref for Salt {
    type Target = [u8; 16];

    #[inline]
    fn deref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::ops::DerefMut for Salt {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for Salt {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for Salt {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::Range<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<std::ops::RangeFull> for Salt {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::RangeFull) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<usize> for Salt {
    type Output = u8;

    #[inline]
    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl std::ops::IndexMut<usize> for Salt {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}

pub struct KTag(pub [u8; 64]);

impl KTag {
    pub fn from_slice(raw: &[u8]) -> Option<KTag> {
        if raw.len() != 64 { return None }
        let mut k = [0u8; 64];

        (0..64).for_each(|i| {
            k[i] = raw[i].clone();
        });
        Some(KTag(k))
    }
}

impl Drop for KTag {
    fn drop(&mut self) {
        let &mut KTag(ref mut v) = self;
        memzero(v);
    }
}

impl std::ops::Deref for KTag {
    type Target = [u8; 64];

    #[inline]
    fn deref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::ops::DerefMut for KTag {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8; 64] {
        &mut self.0
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for KTag {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for KTag {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::Range<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<std::ops::RangeFull> for KTag {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::RangeFull) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<usize> for KTag {
    type Output = u8;

    #[inline]
    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl std::ops::IndexMut<usize> for KTag {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    //use std::time::{Duration, Instant};
    //use std::io::prelude::*;
    //use std::io::SeekFrom;

    #[test]
    fn test_encrypt() {
        use crypt::Crypt as Crypt;

        let paswd      = "ReallySecurePassword12345";
        let path       = "mars.gif";
        let mut test_crypt = Crypt::init(paswd, path)
            .expect("couldn't init crypt!")
            .unwrap();

        let e_result = test_crypt.encrypt()
            .expect("couldn't encrypt!");

        assert!(e_result.unwrap());
    }

    #[test]
    fn test_decrypt() {
        use crypt::Crypt as Crypt;

        std::thread::sleep(std::time::Duration::from_secs(2));

        let paswd      = "ReallySecurePassword12345";
        let path       = "mars.gif";
        let mut test_crypt = Crypt::init(paswd, path)
            .expect("couldn't init crypt!")
            .unwrap();

        let d_result = test_crypt.decrypt()
            .expect("couldn't decrypt!");

        assert!(d_result.unwrap());
    }

    /*#[test]
    fn test_crypt_init() {
        use crypt::Crypt as Crypt;

        let paswd       = "ReallySecurePassword12345";
        let path        = "cent.iso";
        let test_crypt1 = Crypt::init(paswd, path);

        assert!(test_crypt1.is_ok());
        assert!(test_crypt1.unwrap().is_some());

        let path2       = "log1";
        let test_crypt2 = Crypt::init(paswd, path2);

        assert!(test_crypt2.is_ok());
        assert!(test_crypt2.unwrap().is_some());
    }

    // most of these need unwraps, etc
    //#[test]
    fn test_chunk_map() {
        let mb = 1024*1024;

        let mut timer = Instant::now();
        let m = cipher::chunk_map_from_size(mb*1500 + 123).unwrap();
        println!("{:?}", timer.elapsed());
        assert!(m[0].start == 0 && m[0].end == mb);
        assert!(m[m.len()-1].end != m[m.len()-1].start + mb);

        println!("******");

        timer = Instant::now();
        let s = cipher::chunk_map_from_size(mb+54).unwrap();
        println!("{:?}", timer.elapsed());
        assert!(s.len() == 2);
        assert!(s[1].end == mb+54);

        println!("******");

        timer = Instant::now();
        let g = cipher::chunk_map_from_size(64).unwrap();
        println!("{:?}", timer.elapsed());
        assert!(g.len() == 1);
        assert!(g[0].end == 64);
    }

    //#[test]
    fn test_cipher_print() {
        let csalt = rust_sodium::randombytes::randombytes(16);
        let asalt = rust_sodium::randombytes::randombytes(16);
        let paswd = "ReallySecurePassword12345";

        let timer = Instant::now();
        let c = cipher::Cipher::from_argon(paswd, &csalt, &asalt);
        print!("{:?}\n{:?}\n------", c.unwrap(), timer.elapsed());
    }

    //#[test]
    fn test_fail_open_keystore_new() {
        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";

        let ks1   = key_store::KeyStore::new_from(paswd, path);
        assert!(ks1.is_some());
        let c1 = ks1.unwrap();

        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .expect("no");

        f.seek(SeekFrom::Start(32));
        f.write_all(b"hello world"); // change the first bit of the hmac to hello world

        let ks2 = key_store::KeyStore::new_from(paswd, path);
        assert!(ks2.is_some());

        let c2 = ks2.unwrap();

        assert!(c1.get_crypt_key() == c2.get_crypt_key());

        assert!(c2.authenticated == false);

        print!("ks1:{:?}\nks2:{:?}", c1.key, c2.key);
    }

    //#[test]
    fn test_pass_open_keystore_new() {
        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";
        let ks1   = key_store::KeyStore::new_from(paswd, path);
        assert!(ks1.is_some());
        let c1 = ks1.unwrap();

        let ks2 = key_store::KeyStore::new_from(paswd, path);
        assert!(ks2.is_some());

        let c2 = ks2.unwrap();

        assert!(c1.get_crypt_key() == c2.get_crypt_key());

        assert!(c2.authenticated == true);

        print!("ks1:{:?}\nks2:{:?}", c1.key, c2.key);
    }

    //#[test]
    fn test_add_ent_to_keystore() {
        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";

        let ks = key_store::KeyStore::new_from(paswd, path);
        assert!(ks.is_some());
        let dt = [0u8; 160];
        ks.unwrap().add_entry(&dt[0..64], &dt[64..80], &dt[80..96], &dt[96..]);

        let cnt = ::std::fs::metadata(path).expect("no check").len();
        assert!(cnt > 96);
    }

    //#[test]
    fn test_get_ent_from_keystore() {
        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";

        let mut ks = key_store::KeyStore::new_from(paswd, path).expect("ks error");
        let dt = [0u8; 64];

        assert!(ks.get_entry(&dt).is_some());
    }

    //#[test]
    fn test_update_ent_from_keystore() {
        use ::tiny_keccak::Keccak;

        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";

        let mut ks = key_store::KeyStore::new_from(paswd, path).expect("ks error");
        let dt = [0u8; 64];

        let mut h = Keccak::new_keccak512();
        h.update(&ks.get_own_auth()[..]);
        h.update(&ks.get_own_final()[..]);
        h.update(&rust_sodium::randombytes::randombytes(2)[..]);
        h.update(b"the hash");

        let mut r = [0u8; 64];
        h.finalize(&mut r);

        ks.add_entry(&r, &dt[0..16], &dt[0..16], &dt[0..64]);
        ks.update_entry(&r, &dt[0..16], &dt[0..16], &r);

        assert!(ks.current[0..64] == r[..]);
    }*/
}
