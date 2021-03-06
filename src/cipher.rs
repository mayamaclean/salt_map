/// this module is mainly for convenience structs and functions
/// associated with parallel authenticated en/decryption

// contains 'shared' cipher and auth states plus
// a key for use with the final keccak hmac
pub struct Cipher {
    pub keys: ::CryptKey,
    pub nons: ::CryptNon,
    pub auth: ::AuthKey,
    pub afin: ::AuthKey,
}

impl Drop for Cipher {
    fn drop(&mut self) {
        (0..32).for_each(|i| { self.keys.0[i] = 0u8; });
        (0..24).for_each(|i| { self.nons.0[i] = 0u8; });
        (0..16).for_each(|i| {
            self.auth.0[i] = 0u8;
            self.afin.0[i] = 0u8;
        });
    }
}

impl Cipher {
    fn from_vecs(crypt_raw: &[u8], auth_raw: &[u8]) -> Option<Cipher> {
        if crypt_raw.len() < 56 || auth_raw.len() < 32 { return None }

        Some(Cipher {
            keys: ::CryptKey::from_slice(&crypt_raw[0..32]).unwrap(),
            nons: ::CryptNon::from_slice(&crypt_raw[32..56]).unwrap(),
            auth: ::AuthKey::from_slice(&auth_raw[0..16]).unwrap(),
            afin: ::AuthKey::from_slice(&auth_raw[16..32]).unwrap(),
        })
    }

    pub fn from_argon(password: &str, crypt_salt: &[u8], auth_salt: &[u8], mem: u32) -> Option<Cipher> {
        if  crypt_salt.len() < 16 ||
            auth_salt.len() < 16  ||
            password.len() < 16
            {
                return None;
            }

        use argon2::{Config, ThreadMode, Variant, Version};

        let ac = Config {
            ad: &[],
            hash_length: 64,
            lanes: 2,
            mem_cost: mem,
            secret: &[],
            thread_mode: ThreadMode::Parallel,
            time_cost: 3,
            variant: Variant::Argon2id,
            version: Version::Version13,
        };

        let mut craw: Vec<u8> = ::argon2::hash_raw(password.as_bytes(), crypt_salt, &ac).unwrap();
        let mut araw: Vec<u8> = ::argon2::hash_raw(password.as_bytes(), auth_salt, &ac).unwrap();

        let c = Cipher::from_vecs(&craw[..], &araw[..]);

        ::memzero(&mut craw);
        ::memzero(&mut araw);

        c
    }

    pub fn auth(&self) -> &[u8] {
        &self.auth.0[..]
    }

    pub fn f_auth(&self) -> &[u8] {
        &self.afin.0[..]
    }
}

pub fn align(length: usize)
  -> usize
{
    if (length % (1024 * 1024)) == 0 {
        return length / (1024 * 1024)
    }
    (length / (1024 * 1024)) + 1
}

impl ::std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "\n------\nCipher:\n*CryptKey:  {:?}\n*CryptNon:  {:?}\n*AuthKey:   {:?}\n*FinalAuth: {:?}\n------\n",
               &self.keys[..], &self.nons[..], &self.auth[..], &self.afin[..])
    }
}
