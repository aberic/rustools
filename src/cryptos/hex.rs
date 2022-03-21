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

use crate::errors::{Errs, Results};

#[derive(Debug, Clone)]
pub struct Hex;

pub trait HexEncoder<T> {
    fn encode(bytes: T) -> String;
}

pub trait HexDecoder<T> {
    fn decode(src: T) -> Results<Vec<u8>>;
}

impl HexEncoder<&[u8]> for Hex {
    fn encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
}

impl HexEncoder<Vec<u8>> for Hex {
    fn encode(bytes: Vec<u8>) -> String {
        hex::encode(bytes.as_slice())
    }
}

impl HexEncoder<&str> for Hex {
    fn encode(bytes: &str) -> String {
        hex::encode(bytes)
    }
}

impl HexEncoder<String> for Hex {
    fn encode(bytes: String) -> String {
        hex::encode(bytes)
    }
}

impl HexDecoder<&str> for Hex {
    fn decode(src: &str) -> Results<Vec<u8>> {
        match hex::decode(src) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("base64 decode", err)),
        }
    }
}

impl HexDecoder<String> for Hex {
    fn decode(src: String) -> Results<Vec<u8>> {
        match hex::decode(src.as_str()) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("base64 decode", err)),
        }
    }
}

#[cfg(test)]
mod hex_test {
    use crate::cryptos::hex::{HexDecoder, HexEncoder};
    use crate::cryptos::hex::Hex;

    #[test]
    fn hex_test() {
        let src = "hello world!";

        let ber = Hex::encode(src);
        let her = hex::encode(src);
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Hex::decode(ber).unwrap();
        assert_eq!(src.as_bytes(), bdr.as_slice());

        let ber = Hex::encode(src.to_string());
        let her = hex::encode(src.to_string());
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Hex::decode(ber).unwrap();
        assert_eq!(src.as_bytes(), bdr.as_slice());

        let ber = Hex::encode(src.as_bytes().to_vec());
        let her = hex::encode(src.as_bytes().to_vec());
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Hex::decode(ber).unwrap();
        assert_eq!(src.as_bytes(), bdr.as_slice());

        let ber = Hex::encode(src.as_bytes());
        let her = hex::encode(src);
        println!("ber = {}\nhex = {}", ber, her);
        let bdr = Hex::decode(ber.as_str()).unwrap();
        assert_eq!(src.as_bytes(), bdr.as_slice());
    }
}

