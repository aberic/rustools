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

use std::ops::Add;

use crc::{Crc, CRC_16_IBM_SDLC, CRC_32_ISCSI, CRC_64_ECMA_182, CRC_8_BLUETOOTH};
use openssl::hash::{Hasher, MessageDigest};

use crate::cryptos::Hex;
use crate::cryptos::hex::HexEncoder;
use crate::errors::{Errs, Results};
use crate::strings::Strings;

#[derive(Debug, Clone)]
pub struct Hash;

pub trait HashHandler<T> {
    fn digest(md: MessageDigest, content: T) -> Results<String>;

    fn md5(content: T) -> String;

    fn md516(content: T) -> String;

    fn sm3(content: T) -> String;

    fn sha1(content: T) -> String;

    fn sha256(content: T) -> String;

    fn crc8(content: T) -> u8;

    fn crc16(content: T) -> u16;

    fn crc32(content: T) -> u32;

    fn crc64(content: T) -> u64;
}

impl HashHandler<&[u8]> for Hash {
    fn digest(md: MessageDigest, bytes: &[u8]) -> Results<String> {
        digest(md, bytes)
    }

    fn md5(bytes: &[u8]) -> String {
        md5(bytes)
    }

    fn md516(bytes: &[u8]) -> String {
        md516(bytes)
    }

    fn sm3(bytes: &[u8]) -> String {
        digest(MessageDigest::sm3(), bytes).unwrap()
    }

    fn sha1(bytes: &[u8]) -> String {
        digest(MessageDigest::sha1(), bytes).unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        digest(MessageDigest::sha256(), bytes).unwrap()
    }

    fn crc8(bytes: &[u8]) -> u8 {
        crc8(bytes)
    }

    fn crc16(bytes: &[u8]) -> u16 {
        crc16(bytes)
    }

    fn crc32(bytes: &[u8]) -> u32 {
        crc32(bytes)
    }

    fn crc64(bytes: &[u8]) -> u64 {
        crc64(bytes)
    }
}

impl HashHandler<Vec<u8>> for Hash {
    fn digest(md: MessageDigest, bytes: Vec<u8>) -> Results<String> {
        digest(md, bytes.as_slice())
    }

    fn md5(bytes: Vec<u8>) -> String {
        md5(bytes.as_slice())
    }

    fn md516(bytes: Vec<u8>) -> String {
        md516(bytes.as_slice())
    }

    fn sm3(bytes: Vec<u8>) -> String {
        digest(MessageDigest::sm3(), bytes.as_slice()).unwrap()
    }

    fn sha1(bytes: Vec<u8>) -> String {
        digest(MessageDigest::sha1(), bytes.as_slice()).unwrap()
    }

    fn sha256(bytes: Vec<u8>) -> String {
        digest(MessageDigest::sha256(), bytes.as_slice()).unwrap()
    }

    fn crc8(bytes: Vec<u8>) -> u8 {
        crc8(bytes.as_slice())
    }

    fn crc16(bytes: Vec<u8>) -> u16 {
        crc16(bytes.as_slice())
    }

    fn crc32(bytes: Vec<u8>) -> u32 {
        crc32(bytes.as_slice())
    }

    fn crc64(bytes: Vec<u8>) -> u64 {
        crc64(bytes.as_slice())
    }
}

impl HashHandler<String> for Hash {
    fn digest(md: MessageDigest, content: String) -> Results<String> {
        digest(md, content.as_bytes())
    }

    fn md5(content: String) -> String {
        md5(content.as_bytes())
    }

    fn md516(content: String) -> String {
        md516(content.as_bytes())
    }

    fn sm3(content: String) -> String {
        digest(MessageDigest::sm3(), content.as_bytes()).unwrap()
    }

    fn sha1(content: String) -> String {
        digest(MessageDigest::sha1(), content.as_bytes()).unwrap()
    }

    fn sha256(content: String) -> String {
        digest(MessageDigest::sha256(), content.as_bytes()).unwrap()
    }

    fn crc8(content: String) -> u8 {
        crc8(content.as_bytes())
    }

    fn crc16(content: String) -> u16 {
        crc16(content.as_bytes())
    }

    fn crc32(content: String) -> u32 {
        crc32(content.as_bytes())
    }

    fn crc64(content: String) -> u64 {
        crc64(content.as_bytes())
    }
}

impl HashHandler<&str> for Hash {
    fn digest(md: MessageDigest, content: &str) -> Results<String> {
        digest(md, content.as_bytes())
    }

    fn md5(content: &str) -> String {
        md5(content.as_bytes())
    }

    fn md516(content: &str) -> String {
        md516(content.as_bytes())
    }

    fn sm3(content: &str) -> String {
        digest(MessageDigest::sm3(), content.as_bytes()).unwrap()
    }

    fn sha1(content: &str) -> String {
        digest(MessageDigest::sha1(), content.as_bytes()).unwrap()
    }

    fn sha256(content: &str) -> String {
        digest(MessageDigest::sha256(), content.as_bytes()).unwrap()
    }

    fn crc8(content: &str) -> u8 {
        crc8(content.as_bytes())
    }

    fn crc16(content: &str) -> u16 {
        crc16(content.as_bytes())
    }

    fn crc32(content: &str) -> u32 {
        crc32(content.as_bytes())
    }

    fn crc64(content: &str) -> u64 {
        crc64(content.as_bytes())
    }
}

impl HashHandler<i32> for Hash {
    fn digest(md: MessageDigest, content: i32) -> Results<String> {
        digest(md, content.to_string().as_bytes())
    }

    fn md5(content: i32) -> String {
        md5(content.to_string().as_bytes())
    }

    fn md516(content: i32) -> String {
        md516(content.to_string().as_bytes())
    }

    fn sm3(content: i32) -> String {
        digest(MessageDigest::sm3(), content.to_string().as_bytes()).unwrap()
    }

    fn sha1(content: i32) -> String {
        digest(MessageDigest::sha1(), content.to_string().as_bytes()).unwrap()
    }

    fn sha256(content: i32) -> String {
        digest(MessageDigest::sha256(), content.to_string().as_bytes()).unwrap()
    }

    fn crc8(content: i32) -> u8 {
        crc8(content.to_string().as_bytes())
    }

    fn crc16(content: i32) -> u16 {
        crc16(content.to_string().as_bytes())
    }

    fn crc32(content: i32) -> u32 {
        i32_to_crc32(content)
    }

    fn crc64(content: i32) -> u64 {
        i64_to_crc64(content as i64)
    }
}

impl HashHandler<i64> for Hash {
    fn digest(md: MessageDigest, content: i64) -> Results<String> {
        digest(md, content.to_string().as_bytes())
    }

    fn md5(content: i64) -> String {
        md5(content.to_string().as_bytes())
    }

    fn md516(content: i64) -> String {
        md516(content.to_string().as_bytes())
    }

    fn sm3(content: i64) -> String {
        digest(MessageDigest::sm3(), content.to_string().as_bytes()).unwrap()
    }

    fn sha1(content: i64) -> String {
        digest(MessageDigest::sha1(), content.to_string().as_bytes()).unwrap()
    }

    fn sha256(content: i64) -> String {
        digest(MessageDigest::sha256(), content.to_string().as_bytes()).unwrap()
    }

    fn crc8(content: i64) -> u8 {
        crc8(content.to_string().as_bytes())
    }

    fn crc16(content: i64) -> u16 {
        crc16(content.to_string().as_bytes())
    }

    fn crc32(content: i64) -> u32 {
        crc32(content.to_string().as_bytes())
    }

    fn crc64(content: i64) -> u64 {
        i64_to_crc64(content)
    }
}

impl HashHandler<f32> for Hash {
    fn digest(md: MessageDigest, content: f32) -> Results<String> {
        digest(md, content.to_string().as_bytes())
    }

    fn md5(content: f32) -> String {
        md5(content.to_string().as_bytes())
    }

    fn md516(content: f32) -> String {
        md516(content.to_string().as_bytes())
    }

    fn sm3(content: f32) -> String {
        digest(MessageDigest::sm3(), content.to_string().as_bytes()).unwrap()
    }

    fn sha1(content: f32) -> String {
        digest(MessageDigest::sha1(), content.to_string().as_bytes()).unwrap()
    }

    fn sha256(content: f32) -> String {
        digest(MessageDigest::sha256(), content.to_string().as_bytes()).unwrap()
    }

    fn crc8(content: f32) -> u8 {
        crc8(content.to_string().as_bytes())
    }

    fn crc16(content: f32) -> u16 {
        crc16(content.to_string().as_bytes())
    }

    fn crc32(content: f32) -> u32 {
        f32_to_crc32(content)
    }

    fn crc64(content: f32) -> u64 {
        f32_to_crc64(content)
    }
}

impl HashHandler<f64> for Hash {
    fn digest(md: MessageDigest, content: f64) -> Results<String> {
        digest(md, content.to_string().as_bytes())
    }

    fn md5(content: f64) -> String {
        md5(content.to_string().as_bytes())
    }

    fn md516(content: f64) -> String {
        md516(content.to_string().as_bytes())
    }

    fn sm3(content: f64) -> String {
        digest(MessageDigest::sm3(), content.to_string().as_bytes()).unwrap()
    }

    fn sha1(content: f64) -> String {
        digest(MessageDigest::sha1(), content.to_string().as_bytes()).unwrap()
    }

    fn sha256(content: f64) -> String {
        digest(MessageDigest::sha256(), content.to_string().as_bytes()).unwrap()
    }

    fn crc8(content: f64) -> u8 {
        crc8(content.to_string().as_bytes())
    }

    fn crc16(content: f64) -> u16 {
        crc16(content.to_string().as_bytes())
    }

    fn crc32(content: f64) -> u32 {
        crc32(content.to_string().as_bytes())
    }

    fn crc64(content: f64) -> u64 {
        f64_to_crc64(content)
    }
}

fn digest(md: MessageDigest, bytes: &[u8]) -> Results<String> {
    match Hasher::new(md) {
        Ok(mut hasher) => match hasher.update(bytes) {
            Ok(()) => match hasher.finish() {
                Ok(d_bytes) => Ok(Hex::encode(d_bytes.to_vec())),
                Err(err) => Err(Errs::strs("hasher finish", err)),
            },
            Err(err) => Err(Errs::strs("hasher update", err)),
        },
        Err(err) => Err(Errs::strs("hasher new", err)),
    }
}

fn md5(bytes: &[u8]) -> String {
    let mut hash = Hasher::new(MessageDigest::md5()).unwrap();
    hash.update(bytes).unwrap();
    let res = hash.finish().unwrap();
    Hex::encode(res.to_vec())
}

fn md516(bytes: &[u8]) -> String {
    Strings::sub(md5(bytes), 8, 24)
}

fn crc8(bytes: &[u8]) -> u8 {
    let crc = Crc::<u8>::new(&CRC_8_BLUETOOTH);
    let mut digest = crc.digest();
    digest.update(bytes);
    digest.finalize()
}

fn crc16(bytes: &[u8]) -> u16 {
    let crc = Crc::<u16>::new(&CRC_16_IBM_SDLC);
    let mut digest = crc.digest();
    digest.update(bytes);
    digest.finalize()
}

fn crc32(bytes: &[u8]) -> u32 {
    let crc = Crc::<u32>::new(&CRC_32_ISCSI);
    let mut digest = crc.digest();
    digest.update(bytes);
    digest.finalize()
}

fn crc64(bytes: &[u8]) -> u64 {
    let crc = Crc::<u64>::new(&CRC_64_ECMA_182);
    let mut digest = crc.digest();
    digest.update(bytes);
    digest.finalize()
}

fn i32_to_crc32(real: i32) -> u32 {
    if real < 0 {
        real.add(2147483647).add(1) as u32
    } else {
        (real as u32).add(2147483648)
    }
}

fn i64_to_crc64(real: i64) -> u64 {
    if real < 0 {
        real.add(9223372036854775807).add(1) as u64
    } else {
        (real as u64).add(9223372036854775807).add(1)
    }
}

fn f32_to_crc32(real: f32) -> u32 {
    if real > 0.0 {
        real.to_bits().add(2147483648)
    } else if real < 0.0 {
        2147483648 - real.to_bits() + 2147483648
    } else {
        2147483648
    }
}

fn f32_to_crc64(real: f32) -> u64 {
    f64_to_crc64(real as f64)
}

fn f64_to_crc64(real: f64) -> u64 {
    if real > 0.0 {
        real.to_bits().add(9223372036854775809)
    } else if real < 0.0 {
        18446744073709551615 - real.to_bits() + 2
    } else {
        9223372036854775809
    }
}

#[cfg(test)]
mod test {
    use crate::cryptos::hash::Hash;
    use crate::cryptos::hash::HashHandler;

    #[test]
    fn md5_test() {
        let str = "test".to_string();
        let md5_1 = Hash::md5(str.clone());
        let md5_2 = Hash::md5(str.clone());
        println!("test md5 1 = {}", md5_1);
        println!("test md5 2 = {}", md5_2);
        let md516_1 = Hash::md516(str.clone());
        let md516_2 = Hash::md516(str.clone());
        println!("test md516 1 = {}", md516_1);
        println!("test md516 2 = {}", md516_2);
    }

    #[test]
    fn sm3_test() {
        let str = "test".to_string();
        let str_u8s = "test".as_bytes();
        let str_v8s = "test".as_bytes().to_vec();

        let sm3_1 = Hash::sm3(str.clone());
        let sm3_2 = Hash::sm3(str.clone());
        let sm3_3 = Hash::sm3(str_u8s);
        let sm3_4 = Hash::sm3(str_v8s.clone());
        println!("test sm3 1 = {}", sm3_1);
        println!("test sm3 2 = {}", sm3_2);
        println!("test sm3 3 = {}", sm3_3);
        println!("test sm3 4 = {}", sm3_4);
        println!("test sm3 5 = {}", sm3_4);
    }

    #[test]
    fn sha1_test() {
        let str = "test".to_string();
        let str_u8s = "test".as_bytes();
        let str_v8s = "test".as_bytes().to_vec();

        let sm3_1 = Hash::sha1(str.clone());
        let sm3_2 = Hash::sha1(str.clone());
        let sm3_3 = Hash::sha1(str_u8s);
        let sm3_4 = Hash::sha1(str_v8s.clone());
        println!("test sm3 1 = {}", sm3_1);
        println!("test sm3 2 = {}", sm3_2);
        println!("test sm3 3 = {}", sm3_3);
        println!("test sm3 4 = {}", sm3_4);
        println!("test sm3 5 = {}", sm3_4);
    }

    #[test]
    fn sha256_test() {
        let str = "test".to_string();
        let str_u8s = "test".as_bytes();
        let str_v8s = "test".as_bytes().to_vec();

        let sm3_1 = Hash::sha256(str.clone());
        let sm3_2 = Hash::sha256(str.clone());
        let sm3_3 = Hash::sha256(str_u8s);
        let sm3_4 = Hash::sha256(str_v8s.clone());
        println!("test sm3 1 = {}", sm3_1);
        println!("test sm3 2 = {}", sm3_2);
        println!("test sm3 3 = {}", sm3_3);
        println!("test sm3 4 = {}", sm3_4);
        println!("test sm3 5 = {}", sm3_4);
    }

    #[test]
    fn crc32_test1() {
        let bytes1 = "test1".as_bytes();
        let bytes2 = "test2".as_bytes();

        println!("bytes1 = {}", Hash::crc32(bytes1));
        println!("bytes1u64 = {}", Hash::crc32(bytes1) as u64);
        println!("bytes2 = {}", Hash::crc32(bytes2));
        println!("bytes2u64 = {}", Hash::crc32(bytes2) as u64);
    }

    #[test]
    fn crc32_test2() {
        let x1: i32 = -1;
        let x2: i32 = -2;
        let x3: i32 = -3;
        let x4: i32 = 301047507;
        let x5: i32 = 1;
        let x6: i64 = 1;
        let x1b = x1.to_be_bytes();
        let x2b = x2.to_be_bytes();
        let x3b = x3.to_be_bytes();
        let x4b = x4.to_be_bytes();
        let x5b = x5.to_be_bytes();
        let x6b = x6.to_be_bytes();

        println!(
            "x1b = {}, bytes = {:#?}",
            Hash::crc32(x1b.to_vec().as_slice()),
            x1b
        );
        println!(
            "x2b = {}, bytes = {:#?}",
            Hash::crc32(x2b.to_vec().as_slice()),
            x2b
        );
        println!(
            "x3b = {}, bytes = {:#?}",
            Hash::crc32(x3b.to_vec().as_slice()),
            x3b
        );
        println!(
            "x4b = {}, bytes = {:#?}",
            Hash::crc32(x4b.to_vec().as_slice()),
            x4b
        );
        println!(
            "x5b = {}, bytes = {:#?}",
            Hash::crc32(x5b.to_vec().as_slice()),
            x5b
        );
        println!(
            "x6b = {}, bytes = {:#?}",
            Hash::crc32(x6b.to_vec().as_slice()),
            x6b
        );

        println!("x1b {} | x1 {}", Hash::crc32(x1b.to_vec().as_slice()), x1);
        println!("x2b {} | x2 {}", Hash::crc32(x2b.to_vec().as_slice()), x2);
        println!("x3b {} | x3 {}", Hash::crc32(x3b.to_vec().as_slice()), x3);
        println!("x4b {} | x4 {}", Hash::crc32(x4b.to_vec().as_slice()), x4);
        println!("x5b {} | x5 {}", Hash::crc32(x5b.to_vec().as_slice()), x5);
        println!("x6b {} | x6 {}", Hash::crc32(x6b.to_vec().as_slice()), x6);
    }

    #[test]
    fn crc64_test1() {
        let bytes1 = "test1".as_bytes();
        let bytes2 = "test2".as_bytes();
        let bytes3 = &[0x00];
        let bytes4 = &0_i32.to_be_bytes();
        let bytes41 = &1_i32.to_be_bytes();
        let i: i32 = -1;
        let bytes42 = &i.to_be_bytes();
        let bytes5 = &0_u64.to_be_bytes();
        let bytes6 = &[0x01];
        let bytes7 = &1_u32.to_be_bytes();
        let bytes8 = &1_i64.to_be_bytes();
        let bytes9 = &[0xff];
        let bytes10 = &16_u64.to_be_bytes();
        let bytes11 = &16_f64.to_be_bytes();

        println!("res1 = {}", Hash::crc64(bytes1));
        println!("res2 = {}", Hash::crc64(bytes2));
        println!("res3 = {}", Hash::crc64(bytes3.to_vec().as_slice()));
        println!("res4 = {}", Hash::crc64(bytes4.to_vec().as_slice()));
        println!("res41 = {}", Hash::crc64(bytes41.to_vec().as_slice()));
        println!("res42 = {}", Hash::crc64(bytes42.to_vec().as_slice()));
        println!("res5 = {}", Hash::crc64(bytes5.to_vec().as_slice()));
        println!("res6 = {}", Hash::crc64(bytes6.to_vec().as_slice()));
        println!("res7 = {}", Hash::crc64(bytes7.to_vec().as_slice()));
        println!("res8 = {}", Hash::crc64(bytes8.to_vec().as_slice()));
        println!("res9 = {}", Hash::crc64(bytes9.to_vec().as_slice()));
        println!("res10 = {}", Hash::crc64(bytes10.to_vec().as_slice()));
        println!("res11 = {}", Hash::crc64(bytes11.to_vec().as_slice()));
    }

    #[test]
    fn crc64_test2() {
        // let x1: i64 = -1;
        let x2: i64 = -2;
        let x3: i64 = -3;
        let x4: i64 = 301047507;
        let x5: i64 = 1;
        // let x1b = x1.to_be_bytes();
        let x2b = x2.to_be_bytes();
        let x3b = x3.to_be_bytes();
        let x4b = x4.to_be_bytes();
        let x5b = x5.to_be_bytes();

        // println!(
        //     "x1b = {}, bytes = {:#?}",
        //     Hash::crc64(x1b.to_vec().as_slice()),
        //     x1b
        // );
        println!(
            "x2b = {}, bytes = {:#?}",
            Hash::crc64(x2b.to_vec().as_slice()),
            x2b
        );
        println!(
            "x3b = {}, bytes = {:#?}",
            Hash::crc64(x3b.to_vec().as_slice()),
            x3b
        );
        println!(
            "x4b = {}, bytes = {:#?}",
            Hash::crc64(x4b.to_vec().as_slice()),
            x4b
        );
        println!(
            "x5b = {}, bytes = {:#?}",
            Hash::crc64(x5b.to_vec().as_slice()),
            x5b
        );
    }

    #[test]
    fn crc64_test3() {
        let sf640 = -123.34523412;
        let sf641: f32 = -0.1;
        let sf642: f32 = -0.0;
        let sf643: f32 = 0.0;
        let sf644 = 0.00;
        let sf645 = 0.0000000000000000000000000001;
        let sf646 = 0.000000000000000000000000001;
        let sf647 = 0.00000000000000000000000001;
        let sf648 = 0.0000000000000000000000001;
        let sf649: f32 = 1.0;
        let sf6410 = 1.34523411233211;
        let sf6411 = 12.3452341;
        let sf6412 = 12.34523411;
        let sf6413 = 12.345234115;
        let sf6414 = 12.345234119;
        let sf6415 = 12.34523412;
        let sf6416 = 12.345234123;
        let sf6417 = 123.34523412;
        println!(
            "u64 = {}, 0 = {}",
            Hash::crc64(sf640),
            sf640
        );
        println!(
            "u64 = {}, 1 = {}",
            Hash::crc64(sf641),
            sf641
        );
        println!(
            "u64 = {}, 2 = {}",
            Hash::crc64(sf642),
            sf642
        );
        println!(
            "u64 = {}, 3 = {}",
            Hash::crc64(sf643),
            sf643
        );
        println!(
            "u64 = {}, 4 = {}",
            Hash::crc64(sf644),
            sf644
        );
        println!(
            "u64 = {}, 5 = {}",
            Hash::crc64(sf645),
            sf645
        );
        println!(
            "u64 = {}, 6 = {}",
            Hash::crc64(sf646),
            sf646
        );
        println!(
            "u64 = {}, 7 = {}",
            Hash::crc64(sf647),
            sf647
        );
        println!(
            "u64 = {}, 8 = {}",
            Hash::crc64(sf648),
            sf648
        );
        println!(
            "u64 = {}, 9 = {}",
            Hash::crc64(sf649),
            sf649
        );
        println!(
            "u64 = {}, 10 = {}",
            Hash::crc64(sf6410),
            sf6410
        );
        println!(
            "u64 = {}, 11 = {}",
            Hash::crc64(sf6411),
            sf6411
        );
        println!(
            "u64 = {}, 12 = {}",
            Hash::crc64(sf6412),
            sf6412
        );
        println!(
            "u64 = {}, 13 = {}",
            Hash::crc64(sf6413),
            sf6413
        );
        println!(
            "u64 = {}, 14 = {}",
            Hash::crc64(sf6414),
            sf6414
        );
        println!(
            "u64 = {}, 15 = {}",
            Hash::crc64(sf6415),
            sf6415
        );
        println!(
            "u64 = {}, 16 = {}",
            Hash::crc64(sf6416),
            sf6416
        );
        println!(
            "u64 = {}, 17 = {}",
            Hash::crc64(sf6417),
            sf6417
        );

        println!();

        let i0: i64 = -9223372036854775808;
        let i1: i64 = -9223372036854775807;
        let i2 = -1;
        let i3 = -0;
        let i4 = 0;
        let i5 = 1;
        let i6: i64 = 9223372036854775805;
        let i7: i64 = 9223372036854775806;
        println!(
            "i64 = {}, i0 = {}",
            Hash::crc64(i0),
            i0
        );
        println!(
            "i64 = {}, i1 = {}",
            Hash::crc64(i1),
            i1
        );
        println!(
            "i64 = {}, i2 = {}",
            Hash::crc64(i2),
            i2
        );
        println!(
            "i64 = {}, i3 = {}",
            Hash::crc64(i3),
            i3
        );
        println!(
            "i64 = {}, i4 = {}",
            Hash::crc64(i4),
            i4
        );
        println!(
            "i64 = {}, i5 = {}",
            Hash::crc64(i5),
            i5
        );
        println!(
            "i64 = {}, i6 = {}",
            Hash::crc64(i6),
            i6
        );
        println!(
            "i64 = {}, i7 = {}",
            Hash::crc64(i7),
            i7
        );
    }

    #[test]
    fn crc64_test4() {
        let t1 = String::from("test1");
        let t2 = String::from("test2");
        let bytes1 = "test1".as_bytes();
        let bytes2 = "test2".as_bytes();
        let x1 = String::from("-1");
        let x2 = String::from("-2094967294");
        let x3 = String::from("-8446744073709551615");
        let x4 = String::from("18446744073709551615");

        println!("bytes1 = {}", Hash::crc64(bytes1));
        println!("t1 = {}", Hash::crc64(t1));
        println!("bytes2 = {}", Hash::crc64(bytes2));
        println!("t2 = {}", Hash::crc64(t2));
        println!("x1 = {}", Hash::crc64(x1));
        println!("x2 = {}", Hash::crc64(x2));
        println!("x3 = {}", Hash::crc64(x3));
        println!("x4 = {}", Hash::crc64(x4));

        let m: u64 = 1 << 63;
        println!("2^64 = {}", m);

        let uu: u32 = 1988888;
        let uu64 = uu as u64;
        let uu32 = uu64 as u32;
        println!("u1 = {}", uu);
        println!("u2 = {}", uu64);
        println!("u3 = {}", uu32);
    }
}

