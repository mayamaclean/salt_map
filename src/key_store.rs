/// this module defines a file structure and associated
/// functions for querying an encrypted key/value store
/// as well as assuring its own authenticity
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::{Seek, SeekFrom};
use ::cipher::Cipher as Cipher;

pub struct Header(pub [u8; 96]);

impl Header {
    #[inline]
    pub fn csalt(&self) -> &[u8] {
        &self.0[0..16]
    }

    #[inline]
    pub fn asalt(&self) -> &[u8] {
        &self.0[16..32]
    }

    #[inline]
    pub fn hmac(&self) -> &[u8] {
        &self.0[32..96]
    }

    pub fn from_pieces(csalt: &[u8],
                       asalt: &[u8],
                       hmac: &[u8])
      -> Option<Header>
    {
        if csalt.len() != 16 { return None }
        if asalt.len() != 16 { return None }
        if hmac.len()  != 64 { return None }

        let mut h = [0u8; 96];

        h[0..16].clone_from_slice(csalt);
        h[16..32].clone_from_slice(asalt);
        h[32..96].clone_from_slice(hmac);

        Some(Header(h))
    }
}

pub struct Entry(pub [u8; 160]);

impl Entry {
    #[inline]
    pub fn name(&self) -> &[u8] {
        &self.0[0..64]
    }

    #[inline]
    pub fn crypt(&self) -> &[u8] {
        &self.0[64..80]
    }

    #[inline]
    pub fn auth(&self) -> &[u8] {
        &self.0[80..96]
    }

    #[inline]
    pub fn hmac(&self) -> &[u8] {
        &self.0[96..160]
    }

    fn from_pieces(name_hash: &[u8],
                       csalt: &[u8],
                       asalt: &[u8],
                       file_hash: &[u8])
      -> Option<Entry>
    {
        if name_hash.len() != 64 { return None }
        if csalt.len()     != 16 { return None }
        if asalt.len()     != 16 { return None }
        if file_hash.len() != 64 { return None }

        let mut e = [0u8; 160];

        e[0..64].clone_from_slice(name_hash);
        e[64..80].clone_from_slice(csalt);
        e[80..96].clone_from_slice(asalt);
        e[96..160].clone_from_slice(file_hash);

        Some(Entry(e))
    }

    pub fn update_tag(&mut self,
                      tag: &[u8])
      -> bool
    {
        if tag.len() != 64 { return false }

        self[96..160].clone_from_slice(&tag[..]);

        true
    }
}

// change io methods' signatures to fn() -> Result<Option<_>, ::std::io::Error>
pub struct KeyStore {
    pub current: Entry,
    pub key: Cipher,
    pub backing: String,
    pub authenticated: bool,
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        (0..self.current.0.len()).for_each(|i| { self.current[i] = 0u8; })
    }
}

impl KeyStore {
    pub fn get_own_auth(&self) -> &::AuthKey {
        &self.key.auth
    }

    pub fn get_own_final(&self) -> &::AuthKey {
        &self.key.afin
    }

    fn create_from(pass: &str,
                   path: &str)
      -> Result<Option<KeyStore>, ::std::io::Error>
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        let csalt = ::Salt::from_slice(&mut ::random(16))
            .expect("rng error");
        let asalt = ::Salt::from_slice(&mut ::random(16))
            .expect("rng error");

        let c = Cipher::from_argon(pass,
                                   &*csalt,
                                   &*asalt,
                                   64*1024) // change for actual use
            .expect("kdf error");

        let mut h = ::Keccak::new_keccak512();
        h.update(c.auth());
        h.update(c.f_auth());
        let mut r = [0u8; 64];
        h.finalize(&mut r);

        let header = match Header::from_pieces(&*csalt,
                                               &*asalt,
                                               &r)
        {
            Some(x) => x,
            None    => return Ok(None),
        };

        f.seek(SeekFrom::Start(0))?;
        f.write(&header[..])?;

        println!("******\nwriting csalt: {:?}\nwriting asalt: {:?}",
            &header.csalt(),
            &header.asalt());

        Ok(Some(
        KeyStore {
            current: Entry([0u8; 160]),
            key: c,
            backing: String::from(path),
            authenticated: true,
        }))
    }

    pub fn new_from(pass: &str,
                    path: &str)
      -> Result<Option<KeyStore>, ::std::io::Error>
    {
        let mdata = ::std::fs::metadata(path);

        if !mdata.is_ok() {
            return Ok(KeyStore::create_from(pass, path)?)
        }

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let mut header = Header([0u8; 96]);
        f.read(&mut *header)?;

        let c = Cipher::from_argon(pass,
                                   &header.csalt(),
                                   &header.asalt(),
                                   64*1024) // change for actual use
            .expect("kdf error");

        println!("******\ncsalt: {:?}\nasalt: {:?}",
            &header.csalt(),
            &header.asalt());

        let mut h = ::Keccak::new_keccak512();
        h.update(c.auth());
        h.update(c.f_auth());

        let len = mdata.unwrap().len();

        let mut buf = Vec::with_capacity(len as usize);
        f.read_to_end(&mut buf)?;
        h.update(&buf[..]);

        let mut r = ::KTag([0u8; 64]);
        h.finalize(&mut *r);

        println!("read: {:?}\nmade: {:?}",
            &header[32..48],
            &r[..16]);

        let a = ::memcmp(header.hmac(), &*r);

        Ok(Some(
        KeyStore {
            current: Entry([0u8; 160]),
            key: c,
            backing: String::from(path),
            authenticated: a,
        }))
    }

    fn update_hmac(&self)
      -> Result<Option<bool>, ::std::io::Error>
    {
        let mut h = ::Keccak::new_keccak512();
        h.update(self.key.auth());
        h.update(self.key.f_auth());

        let f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.backing)?;

        let mut map = unsafe { ::MmapMut::map_mut(&f)? };

        h.update(&map[96..]);

        let mut r = ::KTag([0u8; 64]);
        h.finalize(&mut *r);

        println!("updating with: {:?}\n\n",
            &r[..16]);

        map[32..96].clone_from_slice(&*r);
        map.flush()?; // this should catch errors and write the relevant entry to a backup

        Ok(Some(true))
    }

    pub fn add_entry(&self,
                     name_hash: &[u8],
                     csalt: &[u8],
                     asalt: &[u8],
                     file_hash: &[u8])
      -> Result<Option<bool>, ::std::io::Error>
    {
        if self.authenticated == false
        { return Ok(Some(false)) }

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(&self.backing)?;

        let mut ent = Entry::from_pieces(name_hash,
                                         csalt,
                                         asalt,
                                         file_hash)
            .expect("no entry");

        let mdata = ::std::fs::metadata(&self.backing)?;
        let len = mdata.len();
        let cnt = (len-96)/160;

        println!("using ic {}",
            cnt*3);
        println!("writing entry: {:?}",
            &ent[..]);

        ::xcc::stream_xor_ic_inplace(&mut ent[..],
                                     &self.key.nons,
                                     cnt*3,
                                     &self.key.keys);

        f.seek(SeekFrom::End(0))?;
        f.write_all(&ent[..])?; // this should catch errors and write the relevant entry to a backup

        Ok(self.update_hmac()?) // this should catch errors and write the relevant entry to a backup
    }

    pub fn add_whole_entry(&self, e: &Entry) -> Result<Option<bool>, ::std::io::Error> {
        Ok(self.add_entry(e.name(), e.crypt(), e.auth(), e.hmac())?)
    }

    pub fn get_entry(&mut self, name_hash: &[u8]) -> Result<Option<u64>, ::std::io::Error> {
        if self.authenticated != true
        { return Ok(None) }

        if name_hash.len() != 64
        { return Ok(None) }

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.backing)?;

        let map = unsafe {
            ::MmapOptions::new()
                .offset(96)
                .map_mut(&f)?
            };

        println!("looking for: {:?}",
            &name_hash[0..16]);

        for e in map.chunks(160).enumerate() {
            self.current.0.clone_from_slice(&e.1[..]);

            ::xcc::stream_xor_ic_inplace(&mut self.current.0,
                                         &self.key.nons,
                                         (e.0*3) as u64,
                                         &self.key.keys);

            println!("using ic: {}",
                e.0*3);

            // todo: check how this branch gets interpreted, leaving for now out of curiosity
            if ::memcmp(&self.current.0[..64], name_hash) {
                println!("\nfound entry:\n{:?}\n",
                    &self.current[..]);

                return Ok(Some(e.0 as u64))
            }
        }

        return Ok(None)
    }

    fn update_entry_with_pieces(&mut self,
                                name_hash: &[u8],
                                csalt: &[u8],
                                asalt: &[u8],
                                file_hash: &[u8])
        -> Result<Option<bool>, ::std::io::Error>
    {
        if self.authenticated != true
        { return Ok(Some(false)) }

        if name_hash.len() != 64 { return Ok(None) }
        if csalt.len()     != 16 { return Ok(None) }
        if asalt.len()     != 16 { return Ok(None) }
        if file_hash.len() != 64 { return Ok(None) }

        let index = match self.get_entry(name_hash)? {
            Some(x) => x,
            None    => return Ok(None),
        };

        self.current = match Entry::from_pieces(name_hash,
                                                csalt,
                                                asalt,
                                                file_hash)
        {
            Some(x) => x,
            None    => return Ok(None),
        };

        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(&self.backing)?;

        let mut map = unsafe {
            ::MmapOptions::new()
                .offset(96 + 160 * index)
                .len(160)
                .map_mut(&f)?
            };

        let mut out = Entry(self.current.0);
        ::xcc::stream_xor_ic_inplace(&mut out[..],
                                     &self.key.nons,
                                     (index*3) as u64,
                                     &self.key.keys);

        map.clone_from_slice(&out[..]);

        map.flush()?;

        Ok(self.update_hmac()?)
    }

    fn update_entry(&mut self,
                    ent: Entry)
      -> Result<Option<bool>, ::std::io::Error>
    {
        if self.authenticated == false
        { return Ok(Some(false)) }

        Ok(self.update_entry_with_pieces(ent.name(),
                                         ent.crypt(),
                                         ent.auth(),
                                         ent.hmac())?)
    }

    pub fn update_entry_by_tag(&mut self,
                               idx: &[u8],
                               tag: &[u8])
      -> Result<Option<bool>, ::std::io::Error>
    {
        if self.authenticated == false
        { return Ok(Some(false)) }

        if self.get_name() != idx {
            if self.get_entry(idx)?.is_none()
            { return Ok(None) }
        }

        if !self.current.update_tag(tag)
        { return Ok(None) }

        let tmp = Entry(self.current.clone());
        Ok(self.update_entry(tmp)?)
    }

    fn get_name(&self)
      -> &[u8]
    { self.current.name() }

    pub fn get_crypt_key(&self)
      -> &[u8]
    { self.current.crypt() }

    pub fn get_auth_key(&self)
      -> &[u8]
    { self.current.auth() }

    pub fn get_hmac(&self)
      -> &[u8]
    { self.current.hmac() }
}

impl ::std::ops::Index<::std::ops::Range<usize>> for Header {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::Range<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::Range<usize>> for Header {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::Range<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for Header {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeFull) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeFull> for Header {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeFull) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<usize> for Header {
    type Output = u8;

    #[inline]
    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<usize> for Header {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for Header {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeTo<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeTo<usize>> for Header {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeTo<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for Header {
    type Output = [u8];

    #[inline]
    fn index(&self, idx: ::std::ops::RangeFrom<usize>) -> &[u8] {
        &self.0[idx]
    }
}

impl ::std::ops::IndexMut<::std::ops::RangeFrom<usize>> for Header {
    #[inline]
    fn index_mut(&mut self, idx: ::std::ops::RangeFrom<usize>) -> &mut [u8] {
        &mut self.0[idx]
    }
}

impl Drop for Header {
    fn drop(&mut self) {
        let &mut Header(ref mut v) = self;
        ::memzero(v);
    }
}

impl ::std::ops::Deref for Header {
    type Target = [u8; 96];

    fn deref(&self) -> &[u8; 96] {
        &self.0
    }
}

impl ::std::ops::DerefMut for Header {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8; 96] {
        &mut self.0
    }
}

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

impl Drop for Entry {
    fn drop(&mut self) {
        let &mut Entry(ref mut v) = self;
        ::memzero(v);
    }
}

impl ::std::ops::Deref for Entry {
    type Target = [u8; 160];

    fn deref(&self) -> &[u8; 160] {
        &self.0
    }
}

impl ::std::ops::DerefMut for Entry {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8; 160] {
        &mut self.0
    }
}
