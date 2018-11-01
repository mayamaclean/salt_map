use blake2_rfc::blake2b::Blake2b as Blake2b;
use ::cipher::Cipher as Cipher;
use ::key_store::KeyStore as KeyStore;

pub struct Crypt {
    path: String,
    ciph: Cipher,
    meta: KeyStore,
    name_tag: ::KTag,
    authenticated: bool,
}

impl Crypt {
    pub fn init(pass: &str, path: &str) -> Result<Option<Crypt>, ::std::io::Error> {
        let cwd = match path.rfind("/") {
            Some(x) => String::from(path.split_at(x).0) + "/", // windows issues ???
            None    => String::from(""),
        };

        let ks_path = String::from(cwd) + ".keystore";

        let mut ks = match KeyStore::new_from(pass, &ks_path)? {
            Some(x) => x,
            None    => return Ok(None),
        };

        if ks.authenticated == false { return Ok(None) } // maybe i should make it panic on non-auth?

        let mut name_hash = ::KTag::from_slice(&mut [0u8; 64])
            .expect("tag error");
        let mut h = ::Keccak::new_keccak512();

        h.update(&ks.get_own_final()[..]);
        h.update(path.as_bytes());
        h.finalize(&mut name_hash.0);

        let is = ks.get_entry(&*name_hash)?;

        if is.is_none() {
            let csalt = ::AuthKey::from_slice(&mut ::random(16))
                .expect("rng error");
            let asalt = ::AuthKey::from_slice(&mut ::random(16))
                .expect("rng error");
            let hmac  = ::KTag([0u8; 64]);

            ks.add_entry(&*name_hash, &*csalt, &*asalt, &*hmac)?;

            return
                Ok(
                Some(
                Crypt {
                    path: String::from(path),
                    ciph: Cipher::from_argon(pass, &*csalt, &*asalt, 64*1024) // change for actual use
                            .expect("kdf error"),
                    meta: ks,
                    name_tag: name_hash,
                    authenticated: true,
                }
            ))
        }
        Ok(
        Some(
        Crypt {
            path: String::from(path),
            ciph: Cipher::from_argon(pass, ks.get_crypt_key(), ks.get_auth_key(), 64*1024) // change for actual use
                    .expect("kdf error"),
            meta: ks,
            name_tag: name_hash,
            authenticated: true
        }
        ))
    }

    pub fn encrypt(&mut self, pass: &str) {
        unimplemented!();
        // should just be: encrypt (map->stack->::xcc or map->::xcc)
        // hash ciphertext in place, update entry for name_tag in ks
    }

    /*pub fn authenticate(&mut self) -> bool {
        use ::blake2_rfc::blake2b::Blake2b;
        use ::chashmap::CHashMap;
        use rayon::prelude::*;
        use std::fs::OpenOptions;

        let timer = ::std::time::Instant::now();

        let hash_store: CHashMap<usize, [u8; 64]> = CHashMap::new();

        println!("opening {}", &self.path);
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.path)
            .expect("no open");

        let mut map = unsafe { ::MmapMut::map_mut(&f).expect("no map") };

        map.par_chunks_mut(1024*1024).enumerate().for_each(|chunk| {
            let mut h = Blake2b::with_key(64, self.meta.auth());

            h.update(&chunk.1[..]);

            let mut r = [0u8; 64];
            r.clone_from_slice(h.finalize().as_bytes());

            //println!("chunk hash sample #{}: {:?}", chunk.0, &r[0..8]);

            hash_store.insert_new(chunk.0, r);
        });

        let mut found = [0u8; 64];
        let mut finaler = ::Keccak::new_keccak512();

        let l = map.len();

        let mut idx = 0;
        println!("map len: {}\nsupposed chunk count: {}", l, l/(1024*1024));
        while idx < l/(1024*1024) { // probably off by one
            let e = hash_store.get(&idx);
            if e.is_some() {
                finaler.update(&e.unwrap()[..]);
                idx += 1;
            }
        }

        finaler.finalize(&mut found);

        let result = ::memcmp(self.meta.hmac(), &found[..]);
        println!("{:?}", timer.elapsed());
        result
    }*/
}
