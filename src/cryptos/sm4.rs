/*
 * Copyright (c) 2020. Aberic - All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use libsm::sm4::Cipher;
use libsm::sm4::cipher_mode::CipherMode;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::errors::{Errs, Results};

pub struct SM4 {
    key: [u8; 16],
    iv: [u8; 16],
    sm4_cipher_mode: Cipher,
}

pub trait SM4Handler {
    fn rand_block() -> [u8; 16];
}

pub trait SM4New1 {
    fn new() -> Results<SM4>;
}

pub trait SM4New2 {
    fn new(mode: CipherMode) -> Results<SM4>;
}

pub trait SM4New3 {
    fn new(key: [u8; 16], mode: CipherMode) -> Results<SM4>;
}

pub trait SM4New4 {
    fn new(key: [u8; 16], iv: [u8; 16], mode: CipherMode) -> Results<SM4>;
}

pub trait SM4SelfHandler {
    fn key(&self) -> [u8; 16];

    fn iv(&self) -> [u8; 16];
}

pub trait SM4Crypt {
    fn encrypt(key: [u8; 16], iv: [u8; 16], data: &[u8]) -> Results<Vec<u8>>;

    fn decrypt(key: [u8; 16], iv: [u8; 16], data: &[u8]) -> Results<Vec<u8>>;
}

pub trait SM4CryptMode {
    fn encrypt(key: [u8; 16], iv: [u8; 16], data: &[u8], mode: CipherMode) -> Results<Vec<u8>>;

    fn decrypt(key: [u8; 16], iv: [u8; 16], data: &[u8], mode: CipherMode) -> Results<Vec<u8>>;
}

pub trait SM4SelfCrypt1 {
    fn encrypt(&self, data: &[u8]) -> Results<Vec<u8>>;

    fn decrypt(&self, data: &[u8]) -> Results<Vec<u8>>;
}

pub trait SM4SelfCrypt2 {
    fn encrypt(&self, iv: &[u8; 16], data: &[u8]) -> Results<Vec<u8>>;

    fn decrypt(&self, iv: &[u8; 16], data: &[u8]) -> Results<Vec<u8>>;
}

impl SM4Handler for SM4 {
    fn rand_block() -> [u8; 16] {
        rand_block()
    }
}

impl SM4New1 for SM4 {
    fn new() -> Results<SM4> {
        create_sm4(rand_block(), rand_block(), CipherMode::Cfb)
    }
}

impl SM4New2 for SM4 {
    fn new(mode: CipherMode) -> Results<SM4> {
        create_sm4(rand_block(), rand_block(), mode)
    }
}

impl SM4New3 for SM4 {
    fn new(key: [u8; 16], mode: CipherMode) -> Results<SM4> {
        create_sm4(key, rand_block(), mode)
    }
}

impl SM4New4 for SM4 {
    fn new(key: [u8; 16], iv: [u8; 16], mode: CipherMode) -> Results<SM4> {
        create_sm4(key, iv, mode)
    }
}

impl SM4SelfHandler for SM4 {
    fn key(&self) -> [u8; 16] {
        self.key.clone()
    }

    fn iv(&self) -> [u8; 16] {
        self.iv.clone()
    }
}

impl SM4SelfCrypt1 for SM4 {
    fn encrypt(&self, data: &[u8]) -> Results<Vec<u8>> {
        match self.sm4_cipher_mode.encrypt(data, &self.iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 encrypt failed!", err)),
        }
    }

    fn decrypt(&self, data: &[u8]) -> Results<Vec<u8>> {
        match self.sm4_cipher_mode.decrypt(data, &self.iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 decrypt failed!", err)),
        }
    }
}

impl SM4SelfCrypt2 for SM4 {
    fn encrypt(&self, iv: &[u8; 16], data: &[u8]) -> Results<Vec<u8>> {
        match self.sm4_cipher_mode.encrypt(data, iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 encrypt failed!", err)),
        }
    }

    fn decrypt(&self, iv: &[u8; 16], data: &[u8]) -> Results<Vec<u8>> {
        match self.sm4_cipher_mode.decrypt(data, iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 decrypt failed!", err)),
        }
    }
}

impl SM4Crypt for SM4 {
    fn encrypt(key: [u8; 16], iv: [u8; 16], data: &[u8]) -> Results<Vec<u8>> {
        match create_sm4(key, iv, CipherMode::Cfb)?.sm4_cipher_mode.encrypt(data, &iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 encrypt failed!", err)),
        }

    }

    fn decrypt(key: [u8; 16], iv: [u8; 16], data: &[u8]) -> Results<Vec<u8>> {
        match create_sm4(key, iv, CipherMode::Cfb)?.sm4_cipher_mode.decrypt(data, &iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 decrypt failed!", err)),
        }

    }
}

impl SM4CryptMode for SM4 {
    fn encrypt(key: [u8; 16], iv: [u8; 16], data: &[u8], mode: CipherMode) -> Results<Vec<u8>> {
        match create_sm4(key, iv, mode)?.sm4_cipher_mode.encrypt(data, &iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 encrypt failed!", err)),
        }
    }

    fn decrypt(key: [u8; 16], iv: [u8; 16], data: &[u8], mode: CipherMode) -> Results<Vec<u8>> {
        match create_sm4(key, iv, mode)?.sm4_cipher_mode.decrypt(data, &iv) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm4 decrypt failed!", err)),
        }
    }
}

fn create_sm4(key: [u8; 16], iv: [u8; 16], mode: CipherMode) -> Results<SM4> {
    Ok(SM4 {
        key,
        iv,
        sm4_cipher_mode: match Cipher::new(&key, mode) {
            Ok(src) => src,
            Err(err) => return Err(Errs::strs("sm4 create_sm4 failed!", err)),
        },
    })
}

fn rand_block() -> [u8; 16] {
    let mut rng = OsRng::default();
    let mut block: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut block[..]);
    block
}

#[cfg(test)]
mod sm4_test {
    #[cfg(test)]
    mod sm4_1 {
        use crate::cryptos::sm4::{SM4Crypt, SM4Handler};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let res = SM4::encrypt(key, iv, "test".as_bytes()).unwrap();
            let d_res = SM4::decrypt(key, iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_2 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4CryptMode, SM4Handler};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test2() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let res = SM4::encrypt(key, iv, "test".as_bytes(), CipherMode::Cfb).unwrap();
            let d_res = SM4::decrypt(key, iv, res.as_slice(), CipherMode::Cfb).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_3 {
        use crate::cryptos::sm4::{SM4New1, SM4SelfCrypt1};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let sm4 = SM4::new().unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_4 {
        use crate::cryptos::sm4::{SM4Handler, SM4New1, SM4SelfCrypt2};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let sm4 = SM4::new().unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_5 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4New2, SM4SelfCrypt1};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let sm4 = SM4::new(CipherMode::Cfb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let sm4 = SM4::new(CipherMode::Ctr).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let sm4 = SM4::new(CipherMode::Ofb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_6 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4Handler, SM4New2, SM4SelfCrypt2};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let sm4 = SM4::new(CipherMode::Cfb).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let sm4 = SM4::new(CipherMode::Ctr).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let sm4 = SM4::new(CipherMode::Ofb).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_7 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4Handler, SM4New3, SM4SelfCrypt1};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Cfb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Ctr).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Ofb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_8 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4Handler, SM4New3, SM4SelfCrypt2};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Cfb).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Ctr).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let key = SM4::rand_block();
            let sm4 = SM4::new(key, CipherMode::Ofb).unwrap();
            let iv = SM4::rand_block();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_9 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4Handler, SM4New4, SM4SelfCrypt1};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Cfb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Ctr).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Ofb).unwrap();
            let res = sm4.encrypt("test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }

    #[cfg(test)]
    mod sm4_10 {
        use libsm::sm4::cipher_mode::CipherMode;

        use crate::cryptos::sm4::{SM4Handler, SM4New4, SM4SelfCrypt2};
        use crate::cryptos::sm4::SM4;

        #[test]
        fn sm4_test1() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Cfb).unwrap();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test2() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Ctr).unwrap();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }

        #[test]
        fn sm4_test3() {
            let key = SM4::rand_block();
            let iv = SM4::rand_block();
            let sm4 = SM4::new(key, iv, CipherMode::Ofb).unwrap();
            let res = sm4.encrypt(&iv, "test".as_bytes()).unwrap();
            let d_res = sm4.decrypt(&iv, res.as_slice()).unwrap();
            println!("d_res = {}", String::from_utf8(d_res).unwrap());
        }
    }
}

