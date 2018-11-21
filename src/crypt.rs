/// file auth crypt using keystore type
use blake2_rfc::blake2b::Blake2b as Blake2b;
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use ::chashmap::CHashMap;
use ::cipher::Cipher as Cipher;
use ::key_store::KeyStore as KeyStore;

// impl zeroing password type

pub struct Crypt {
    path: String,
    ciph: Cipher,
    meta: KeyStore,
    name_tag: ::KTag,
    authenticated: Option<bool>,
}

impl Crypt {
    pub fn init(pass: &str,
                path: &str)
      -> Result<Option<Crypt>, ::std::io::Error>
    {
        let cwd = match path.rfind("/") {
            Some(x) => String::from(path.split_at(x).0) + "/", // windows issues ???
            None    => String::from(""),
        };

        let ks_path = String::from(cwd) + ".keystore";

        let mut ks = match KeyStore::new_from(pass, &ks_path)? {
            Some(x) => x,
            None    => return Ok(None),
        };

        if ks.authenticated == false { return Ok(None) }

        let mut name_hash = ::KTag([0u8; 64]);
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
                    authenticated: None,
                }
            ))
        }
        Ok(
        Some(
        Crypt {
            path: String::from(path),
            ciph: Cipher::from_argon(pass,
                                     ks.get_crypt_key(),
                                     ks.get_auth_key(),
                                     64*1024) // change for actual use
                                     .expect("kdf error"),
            meta: ks,
            name_tag: name_hash,
            authenticated: None,
        }
        ))
    }

    pub fn encrypt(&mut self)
      -> Result<Option<bool>, ::std::io::Error>
    {
        let timer = Instant::now();

        println!("encrypting {}", &self.path);
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.path)?;

        let mut map = unsafe { ::MmapMut::map_mut(&f)? };

        let hash_store: CHashMap<usize, ::KTag> = CHashMap::with_capacity(map.len() / (1024*1024));

        map.par_chunks_mut(1024*1024).enumerate().for_each(|c| {
            //let mut t_timer = Instant::now();

            let mut chunk = c.1;
            let mut work  = Vec::with_capacity(chunk.len());
            work.write_all(chunk)
                .expect("error reading chunk");

            ::xcc::stream_xor_ic_inplace(&mut work[..],
                                         &self.ciph.nons,
                                         c.0 as u64 * (1024*1024/64),
                                         &self.ciph.keys);

            //let c_time = t_timer.elapsed();

            //t_timer = Instant::now();

            let mut h = Blake2b::with_key(64, &self.ciph.auth[..]);

            h.update(&work[..]);

            let mut r = ::KTag([0u8; 64]);
            r.clone_from_slice(h.finalize().as_bytes());

            hash_store.insert_new(c.0, r);

            chunk.write_all(&work[..])
                .expect("could not write chunk");

            /*println!("crypt #{} took: {:#?}\ntag #{} took: {:#?}",
                chunk.0,
                c_time,
                chunk.0,
                t_timer.elapsed());*/
        });

        let mut tag     = ::KTag([0u8; 64]);
        let mut finaler = ::Keccak::new_keccak512();

        finaler.update(&self.ciph.afin[..]);

        let l = map.len();

        let mut idx = 0;
        println!("map len: {}\nsupposed chunk count: {}",
            l,
            l/(1024*1024));

        while idx < l/(1024*1024) { // probably off by one?
            let e = hash_store.get(&idx);
            if e.is_some() {
                finaler.update(&e.unwrap()[..]);
                idx += 1;
            }
        }

        finaler.finalize(&mut *tag);

        let tmp = ::KTag(self.name_tag.clone());

        self.authenticated = Some(true);

        println!("file took {:#?} to encrypt and tag",
            timer.elapsed());

        Ok(self.meta.update_entry_by_tag(&tmp[..],
                                         &*tag)?)
    }

    pub fn authenticate(&mut self)
      -> Result<Option<bool>, ::std::io::Error>
    {
        let timer = Instant::now();

        println!("opening {}", &self.path);
        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.path)?;

        let map = unsafe { ::MmapMut::map_mut(&f)? };

        let hash_store: CHashMap<usize, ::KTag> = CHashMap::with_capacity(map.len() / (1024*1024));

        map.par_chunks(1024*1024).enumerate().for_each(|chunk| {
            let mut h = Blake2b::with_key(64, &self.ciph.auth[..]);

            h.update(&chunk.1[..]);

            let mut r = ::KTag([0u8; 64]);
            r.clone_from_slice(h.finalize().as_bytes());

            //println!("chunk hash sample #{}: {:?}", chunk.0, &r[0..8]);

            hash_store.insert_new(chunk.0, r);
        });

        let mut found = ::KTag([0u8; 64]);
        let mut finaler = ::Keccak::new_keccak512();

        finaler.update(&self.ciph.afin[..]);

        let l = map.len();

        let mut idx = 0;
        println!("map len: {}\nsupposed chunk count: {}", l, l/(1024*1024));
        while idx < l/(1024*1024) { // probably off by one?
            let e = hash_store.get(&idx);
            if e.is_some() {
                finaler.update(&e.unwrap()[..]);
                idx += 1;
            }
        }

        finaler.finalize(&mut *found);

        let result = ::memcmp(self.meta.get_hmac(), &found[..]);
        println!("authentication took: {:?}", timer.elapsed());
        self.authenticated = Some(result);
        Ok(Some(result))
    }

    pub fn decrypt(&mut self)
      -> Result<Option<bool>, ::std::io::Error>
    {
        if self.authenticated.is_none() {
            match self.authenticate()? {
                Some(false) => return Ok(Some(false)),
                None        => return Ok(None),
                Some(true)  => (),
            }
        }
        if !self.authenticated.unwrap()
        { return Ok(Some(false)) }

        let timer = Instant::now();

        println!("decrypting {}", &self.path);

        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.path)?;

        let mut map = unsafe { ::MmapMut::map_mut(&f)? };

        map.par_chunks_mut(1024*1024).enumerate().for_each(|c| {
            //let mut t_timer = Instant::now();

            let chunk = c.1;

            ::xcc::stream_xor_ic_inplace(chunk,
                                         &self.ciph.nons,
                                         c.0 as u64 * (1024*1024/64),
                                         &self.ciph.keys);

            /*println!("crypt #{} took: {:#?}",
                chunk.0,
                t_timer.elapsed());*/
        });

        println!("file took {:#?} to decrypt",
            timer.elapsed());

        Ok(Some(true))
    }
}
