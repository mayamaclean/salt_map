///test cli
extern crate salt_map;

use salt_map::crypt::Crypt;
use std::env;

fn enc(pass: &str, path: &str) -> Result<Option<bool>, std::io::Error> {
    let mut crypt = match Crypt::init(pass, path)? {
        Some(c) => c,
        None    => return Ok(Some(false)),
    };
    Ok(crypt.encrypt()?)
}

fn dec(pass: &str, path: &str) -> Result<Option<bool>, std::io::Error> {
    let mut crypt = match Crypt::init(pass, path)? {
        Some(c) => c,
        None    => return Ok(Some(false)),
    };
    Ok(crypt.decrypt()?)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mode = args[1].clone();
    let pass = args[2].clone();
    let path = args[3].clone();

    println!("mode: {}\npass: {}\npath: {}", mode, pass, path);

    if mode == "e" {
        match enc(&pass, &path) {
            Ok(Some(r)) => println!("result: {}", r),
            Ok(None)    => println!("none result"),
            Err(e)      => println!("error:\n{:?}", e),
        }
    } else if mode == "d" {
        match dec(&pass, &path) {
            Ok(Some(r)) => println!("result: {}", r),
            Ok(None)    => println!("none result"),
            Err(e)      => println!("error:\n{:?}", e),
        }
    }
}
