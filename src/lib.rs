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

#[macro_use]
extern crate lazy_static;
extern crate phf;

pub use channel::Channel;
pub use compress::Compress;
pub use env::Env;
pub use rands::Rand;
pub use time::Time;
pub use trans::Trans;
use crate::errors::{Errs, Results};

pub mod concurrent;
pub mod cryptos;
mod env;
pub mod errors;
pub mod io;
pub mod json;
pub mod merkle;
pub mod openssl;
mod rands;
pub mod strings;
mod time;
mod trans;
pub mod vectors;
pub mod yaml;
mod channel;
mod compress;
pub mod log;

struct Serde;

enum SerdeType{
    Param, Index
}

impl Serde {
    fn param_string(op: Option<&str>, value: &str) -> Results<String> {
        string(op, SerdeType::Param, value)
    }

    fn param_u64(op: Option<u64>, value: &str) -> Results<u64> {
        u64(op, SerdeType::Param, value)
    }

    fn param_i64(op: Option<i64>, value: &str) -> Results<i64> {
        i64(op, SerdeType::Param, value)
    }

    fn param_f64(op: Option<f64>, value: &str) -> Results<f64> {
        f64(op, SerdeType::Param, value)
    }

    fn param_bool(op: Option<bool>, value: &str) -> Results<bool> {
        bool(op, SerdeType::Param, value)
    }

    fn index_string(op: Option<&str>, value: &str) -> Results<String> {
        string(op, SerdeType::Index, value)
    }

    fn index_u64(op: Option<u64>, value: &str) -> Results<u64> {
        u64(op, SerdeType::Index, value)
    }

    fn index_i64(op: Option<i64>, value: &str) -> Results<i64> {
        i64(op, SerdeType::Index, value)
    }

    fn index_f64(op: Option<f64>, value: &str) -> Results<f64> {
        f64(op, SerdeType::Index, value)
    }

    fn index_bool(op: Option<bool>, value: &str) -> Results<bool> {
        bool(op, SerdeType::Index, value)
    }
}

fn string(op: Option<&str>, serde_type: SerdeType, value: &str) -> Results<String> {
    match op {
        Some(res) => Ok(res.to_string()),
        None => match serde_type {
            SerdeType::Param => Err(Errs::string(format!(
                "param {} not found or can not trans string!",
                value
            ))),
            SerdeType::Index => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                value
            ))),
        }
    }
}

fn u64(op: Option<u64>, serde_type: SerdeType, value: &str) -> Results<u64> {
    match op {
        Some(res) => Ok(res),
        None => match serde_type {
            SerdeType::Param => Err(Errs::string(format!(
                "param {} not found or can not trans u64!",
                value
            ))),
            SerdeType::Index => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                value
            ))),
        }
    }
}

fn i64(op: Option<i64>, serde_type: SerdeType, value: &str) -> Results<i64> {
    match op {
        Some(res) => Ok(res),
        None => match serde_type {
            SerdeType::Param => Err(Errs::string(format!(
                "param {} not found or can not trans i64!",
                value
            ))),
            SerdeType::Index => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                value
            ))),
        }
    }
}

fn f64(op: Option<f64>, serde_type: SerdeType, value: &str) -> Results<f64> {
    match op {
        Some(res) => Ok(res),
        None => match serde_type {
            SerdeType::Param => Err(Errs::string(format!(
                "param {} not found or can not trans f64!",
                value
            ))),
            SerdeType::Index => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                value
            ))),
        }
    }
}

fn bool(op: Option<bool>, serde_type: SerdeType, value: &str) -> Results<bool> {
    match op {
        Some(res) => Ok(res),
        None => match serde_type {
            SerdeType::Param => Err(Errs::string(format!(
                "param {} not found or can not trans bool!",
                value
            ))),
            SerdeType::Index => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                value
            ))),
        }
    }
}