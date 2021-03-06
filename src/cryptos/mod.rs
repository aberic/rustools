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

use crate::errors::Results;
pub use self::hex::Hex;

pub mod base64;
pub mod ca;
pub mod ecdsa;
pub mod hash;
pub mod hex;
pub mod homomorphic;
pub mod key;
pub mod rsa;
pub mod sm2;
pub mod sm4;


pub trait Encoder<T> {
    fn encode(bytes: T) -> String;
}

pub trait Decoder<T> {
    fn decode(src: T) -> Results<Vec<u8>>;
}