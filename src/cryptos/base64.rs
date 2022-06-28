/*
 * Copyright (c) 2021. Aberic - All Rights Reserved.
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

use openssl::base64::{decode_block, encode_block};
use crate::cryptos::{Decoder, Encoder};

use crate::errors::{Errs, Results};

#[derive(Debug, Clone)]
pub struct Base64;

impl Encoder<&[u8]> for Base64 {
    fn encode(bytes: &[u8]) -> String {
        encode_block(bytes)
    }
}

impl Encoder<Vec<u8>> for Base64 {
    fn encode(bytes: Vec<u8>) -> String {
        encode_block(bytes.as_slice())
    }
}

impl Decoder<&str> for Base64 {
    fn decode(src: &str) -> Results<Vec<u8>> {
        match decode_block(src) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("base64 decode", err)),
        }
    }
}

impl Decoder<String> for Base64 {
    fn decode(src: String) -> Results<Vec<u8>> {
        match decode_block(src.as_str()) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("base64 decode", err)),
        }
    }
}

#[cfg(test)]
mod base64_test {
    use crate::cryptos::base64::{Base64, Decoder, Encoder};

    #[test]
    fn base64_test() {
        let src = "hello world!".as_bytes();
        let ber = Base64::encode(src);
        let her = hex::encode(src);
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Base64::decode(ber).unwrap();
        assert_eq!(src, bdr.as_slice());

        let ber = Base64::encode(src.to_vec());
        let her = hex::encode(src);
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Base64::decode(ber).unwrap();
        assert_eq!(src, bdr.as_slice());

        let ber = Base64::encode(src.to_vec());
        let her = hex::encode(src);
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Base64::decode(ber.as_str()).unwrap();
        assert_eq!(src, bdr.as_slice());
    }
}

