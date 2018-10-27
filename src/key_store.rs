/// this module defines a file structure and associated
/// functions for querying an encrypted key/value store
/// as well as assuring its own authenticity

pub struct Entry([u8; 160]);

impl ::std::ops::Index<::std::ops::Range<usize>> for Entry {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::Range<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::Range<usize>> for Entry {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::Range<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for Entry {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeFull) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeFull> for Entry {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeFull) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<usize> for Entry {
    type Output = u8;

    #[inline]
    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<usize> for Entry {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for Entry {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeTo<usize>> for Entry {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeTo<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for Entry {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeFrom<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeFrom<usize>> for Entry {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeFrom<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.0[0..64]
    }

    pub fn crypt(&self) -> &[u8] {
        &self.0[64..80]
    }

    pub fn auth(&self) -> &[u8] {
        &self.0[80..96]
    }

    pub fn hmac(&self) -> &[u8] {
        &self.0[96..160]
    }

    pub fn from_pieces(name_hash: &[u8], csalt: &[u8], asalt: &[u8], file_hash: &[u8]) -> Option<Entry> {
        if name_hash.len() != 64 { return None }
        if csalt.len()     != 16 { return None }
        if asalt.len()     != 16 { return None }
        if file_hash.len() != 64 { return None }

        let mut e = Entry([0u8; 160]);

        (0..64).for_each(|i| {
            e[i]    = name_hash[i];
            e[i+96] = file_hash[i];
        });

        (0..16).for_each(|i| {
            e[i+64] = csalt[i];
            e[i+80] = asalt[i];
        });

        Some(e)
    }
}

pub struct KeyStore {
    pub current: Entry,
    pub key: ::cipher::Cipher,
    pub backing: String,
    pub authenticated: bool,
}

impl KeyStore {
    pub fn get_own_auth(&self) -> &::AuthKey {
        &self.key.auth // wat
    }

    pub fn get_own_final(&self) -> &::AuthKey {
        &self.key.auth
    }

    pub fn create_from(pass: &str, path: &str) -> Option<KeyStore> {
        use ::tiny_keccak::Keccak;
        use std::fs::OpenOptions;
        use std::io::prelude::*;
        use std::io::{Seek, SeekFrom};

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .expect("no file 1");

        let mut header = [0u8; 96];

        let csalt = ::rust_sodium::randombytes::randombytes(16);
        let asalt = ::rust_sodium::randombytes::randombytes(16);

        (0..16).for_each(|i| {
            header[i]    = csalt[i];
            header[i+16] = asalt[i];
         });

        let c = ::cipher::Cipher::from_argon(pass, &csalt, &asalt).expect("no argon 1");

        let mut h = Keccak::new_keccak512();
        h.update(c.auth());
        h.update(c.f_auth());
        h.update(b"no entries");
        let mut r = [0u8; 64];
        h.finalize(&mut r);

        (0..64).for_each(|i| { header[i+32] = r[i]; });
        f.seek(SeekFrom::Start(0)).expect("no seek 1");
        f.write(&header[..]).expect("no write 1");

        Some(KeyStore {
            current: Entry([0u8; 160]),
            key: c,
            backing: String::from(path),
            authenticated: true,
        })
    }

    pub fn new_from(pass: &str, path: &str) -> Option<KeyStore> {
        use ::tiny_keccak::Keccak;
        use std::fs::OpenOptions;
        use std::io::prelude::*;

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("no file 2");

        let mut header = [0u8; 96];
        f.read(&mut header).expect("no read 1");

        let c = ::cipher::Cipher::from_argon(pass, &header[0..16], &header[16..32]).expect("no argon 2");

        let mut h = Keccak::new_keccak512();
        h.update(c.auth());
        h.update(c.f_auth());

        let len = ::std::fs::metadata(path).expect("no check in function 1").len();

        if len > 96 {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).expect("no read to end 1");
            h.update(&buf[..]);
        } else {
            h.update(b"no entries");
        }

        let mut r = [0u8; 64];
        h.finalize(&mut r);

        println!("\n******\nread:\n{:?}\n\nmade:\n{:?}\n******", &header[32..], &r[..]);
        let a = ::rust_sodium::utils::memcmp(&header[32..], &r);

        Some(KeyStore {
            current: Entry([0u8; 160]),
            key: c,
            backing: String::from(path),
            authenticated: a,
        })
    }

    pub fn update_hmac(&self) {
        use ::tiny_keccak::Keccak;
        use std::fs::OpenOptions;
        use memmap::MmapMut;

        let mut h = Keccak::new_keccak512();
        h.update(self.key.auth());
        h.update(self.key.f_auth());

        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.backing)
            .expect("no open");

        let mut map = unsafe { MmapMut::map_mut(&f).expect("no map") };

        h.update(&map[96..]);

        let mut r = [0u8; 64];
        h.finalize(&mut r);

        map[32..96].clone_from_slice(&r);
        map.flush().expect("map flush error");
    }

    pub fn add_entry(&self, name_hash: &[u8], csalt: &[u8], asalt: &[u8], file_hash: &[u8]) {
        use std::fs::OpenOptions;
        use std::io::prelude::*;
        use std::io::{Seek, SeekFrom};

        if self.authenticated == false { return }

        let mut f   = OpenOptions::new().read(true).write(true)
                                        .append(true).open(&self.backing)
                                        .expect("no open");
        let mut ent = Entry::from_pieces(name_hash, csalt, asalt, file_hash).expect("no entry");

        let len = ::std::fs::metadata(&self.backing).expect("no check in function 3").len();
        let cnt = (len-96)/160;

        ::xcc::stream_xor_ic_inplace(&mut ent[..], &self.key.nons, cnt*3, &self.key.keys);

        f.seek(SeekFrom::End(0)).expect("seek err");
        f.write_all(&ent[..]).expect("seek err");

        self.update_hmac();
    }

    pub fn get_entry(&mut self, name_hash: &[u8]) -> Option<u64> {
        use std::fs::OpenOptions;
        use memmap::MmapOptions;

        if self.authenticated != true { return None }

        if name_hash.len() != 64 { return None }

        let f   = OpenOptions::new().read(true).write(true)
                                        .append(true).open(&self.backing)
                                        .expect("no open");

        let map = unsafe { MmapOptions::new().offset(96).map_mut(&f).expect("no map") };

        println!("\n******\nlooking for:\n{:?}", name_hash);

        for e in map.chunks(160).enumerate() {
            self.current.0.clone_from_slice(&e.1[..]);

            ::xcc::stream_xor_ic_inplace(&mut self.current.0, &self.key.nons, (e.0*3) as u64, &self.key.keys);
            println!("using ic: {}", e.0*3);

            if ::rust_sodium::utils::memcmp(&self.current.0[..64], name_hash) {
                println!("******\n");
                return Some(e.0 as u64)
            }
        }

        return None
    }

    pub fn update_entry(&mut self, name_hash: &[u8], csalt: &[u8], asalt: &[u8], file_hash: &[u8]) -> bool {
        use std::fs::OpenOptions;
        use memmap::MmapOptions;

        if self.authenticated != true { return false }

        if name_hash.len() != 64 { return false }
        if csalt.len()     != 16 { return false }
        if asalt.len()     != 16 { return false }
        if file_hash.len() != 64 { return false }

        let index = self.get_entry(name_hash).expect("get error");
        if  index == 0 { return false }

        self.current[..64].clone_from_slice(name_hash);
        self.current[64..80].clone_from_slice(csalt);
        self.current[80..96].clone_from_slice(asalt);
        self.current[96..].clone_from_slice(file_hash);

        let f   = OpenOptions::new().read(true).write(true)
                                        .append(true).open(&self.backing)
                                        .expect("no open");

        let mut map = unsafe { MmapOptions::new().offset(96 + 160 * index).len(160).map_mut(&f).expect("no map") };

        let mut out = Entry(self.current.0);
        ::xcc::stream_xor_ic_inplace(&mut out[..], &self.key.nons, (index*3) as u64, &self.key.keys);
        map.clone_from_slice(&out[..]);

        map.flush().expect("map err");

        self.update_hmac();

        return true
    }

    pub fn get_crypt_key(&self) -> &[u8] {
        self.current.crypt()
    }

    pub fn get_auth_key(&self) -> &[u8] {
        self.current.auth()
    }

    pub fn get_hmac(&self) -> &[u8] {
        self.current.hmac()
    }
}
