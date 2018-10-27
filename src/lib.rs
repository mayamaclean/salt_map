extern crate argon2;
extern crate blake2_rfc;
extern crate memmap;
extern crate rayon;
extern crate rust_sodium;
extern crate tiny_keccak;

pub mod cipher;
pub mod key_store;

use rust_sodium::crypto::stream::xchacha20 as xcc;

pub struct AuthKey(pub [u8; 16]);
pub type CryptKey = rust_sodium::crypto::stream::xchacha20::Key;
pub type CryptNon = rust_sodium::crypto::stream::xchacha20::Nonce;

impl AuthKey {
    pub fn from_slice(raw: &[u8]) -> Option<AuthKey> {
        if raw.len() != 16 { return None }
        let mut k = [0u8; 16];

        (0..16).for_each(|i| { k[i] = raw[i]; });
        Some(AuthKey(k))
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        let &mut AuthKey(ref mut v) = self;
        rust_sodium::utils::memzero(v);
    }
}

impl std::ops::Index<std::ops::Range<usize>> for AuthKey {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::Range<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl std::ops::Index<std::ops::RangeFull> for AuthKey {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: std::ops::RangeFull) -> &[u8] {
        &self.0[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use std::io::prelude::*;
    use std::io::SeekFrom;

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

        let ks1   = key_store::KeyStore::create_from(paswd, path);
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
        let ks1   = key_store::KeyStore::create_from(paswd, path);
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

    #[test]
    fn test_get_ent_from_keystore() {
        use ::tiny_keccak::Keccak;

        let paswd = "ReallySecurePassword12345";
        let path  = "keystore";

        let mut ks = key_store::KeyStore::new_from(paswd, path).expect("ks error");
        let dt = [0u8; 64];

        assert!(ks.get_entry(&dt));
    }
}
