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

use crate::errors::{Errs, Results};

pub struct Strings;

impl Strings {

    /// 字符串截取
    pub fn sub_str(comment: &str, begin: usize, end: usize) -> String {
        sub_string(comment.to_string(), begin, end)
    }

    /// 字符串截取
    pub fn sub(comment: String, begin: usize, end: usize) -> String {
        sub_string(comment, begin, end)
    }

    /// 字符串左边补齐字符，长度为len
    ///
    /// comment 待补齐字符串
    ///
    /// ch 补齐字符
    ///
    /// len 期望补齐后的总长度
    pub fn left_fit_str(comment: &str, ch: char, len: usize) -> String {
        left_fit_string(comment.to_string(), ch, len)
    }

    /// 字符串左边补齐字符，长度为len
    ///
    /// comment 待补齐字符串
    ///
    /// ch 补齐字符
    ///
    /// len 期望补齐后的总长度
    pub fn left_fit(comment: String, ch: char, len: usize) -> String {
        left_fit_string(comment, ch, len)
    }

    /// 字符串左边删除字符
    ///
    /// comment 待操作字符串
    ///
    /// ch 待删除字符
    pub fn left_un_fit_str(comment: &str, ch: char) -> String {
        left_un_fit_string(comment.to_string(), ch)
    }

    /// 字符串左边删除字符
    ///
    /// comment 待操作字符串
    ///
    /// ch 待删除字符
    pub fn left_un_fit(comment: String, ch: char) -> String {
        left_un_fit_string(comment, ch)
    }

    /// 字符串右边补齐字符，长度为len
    ///
    /// comment 待补齐字符串
    ///
    /// ch 补齐字符
    ///
    /// len 期望补齐后的总长度
    pub fn right_fit_str(comment: &str, ch: char, len: usize) -> String {
        right_fit_string(comment.to_string(), ch, len)
    }

    /// 字符串右边补齐字符，长度为len
    ///
    /// comment 待补齐字符串
    ///
    /// ch 补齐字符
    ///
    /// len 期望补齐后的总长度
    pub fn right_fit(comment: String, ch: char, len: usize) -> String {
        right_fit_string(comment, ch, len)
    }

    /// 获取重复len次repeated的字符串
    pub fn repeater_str(repeated: &str, len: usize) -> String {
        repeated_string(repeated, len)
    }

    /// 获取重复len次repeated的字符串
    pub fn repeater(repeated: String, len: usize) -> String {
        repeated_string(repeated.as_str(), len)
    }

    /// 字符串转u8
    pub fn parse_u8_str(comment: &str) -> Results<u8> {
        parse_u8(comment.to_string())
    }

    /// 字符串转u16
    pub fn parse_u16_str(comment: &str) -> Results<u16> {
        parse_u16(comment.to_string())
    }

    /// 字符串转u32
    pub fn parse_u32_str(comment: &str) -> Results<u32> {
        parse_u32(comment.to_string())
    }

    /// 字符串转u64
    pub fn parse_u64_str(comment: &str) -> Results<u64> {
        parse_u64(comment.to_string())
    }

    /// 字符串转u8
    pub fn parse_i8_str(comment: &str) -> Results<i8> {
        parse_i8(comment.to_string())
    }

    /// 字符串转u16
    pub fn parse_i16_str(comment: &str) -> Results<i16> {
        parse_i16(comment.to_string())
    }

    /// 字符串转i32
    pub fn parse_i32_str(comment: &str) -> Results<i32> {
        parse_i32(comment.to_string())
    }

    /// 字符串转i64
    pub fn parse_i64_str(comment: &str) -> Results<i64> {
        parse_i64(comment.to_string())
    }

    /// 字符串转f32
    pub fn parse_f32_str(comment: &str) -> Results<f32> {
        parse_f32(comment.to_string())
    }

    /// 字符串转f64
    pub fn parse_f64_str(comment: &str) -> Results<f64> {
        parse_f64(comment.to_string())
    }

    /// 字符串转bool
    pub fn parse_bool_str(comment: &str) -> Results<bool> {
        parse_bool(comment.to_string())
    }

    /// 字符串转u8
    pub fn parse_u8(comment: String) -> Results<u8> {
        parse_u8(comment)
    }

    /// 字符串转u16
    pub fn parse_u16(comment: String) -> Results<u16> {
        parse_u16(comment)
    }

    /// 字符串转u32
    pub fn parse_u32(comment: String) -> Results<u32> {
        parse_u32(comment)
    }

    /// 字符串转u64
    pub fn parse_u64(comment: String) -> Results<u64> {
        parse_u64(comment)
    }

    /// 字符串转u8
    pub fn parse_i8(comment: String) -> Results<i8> {
        parse_i8(comment)
    }

    /// 字符串转u16
    pub fn parse_i16(comment: String) -> Results<i16> {
        parse_i16(comment)
    }

    /// 字符串转i32
    pub fn parse_i32(comment: String) -> Results<i32> {
        parse_i32(comment)
    }

    /// 字符串转i64
    pub fn parse_i64(comment: String) -> Results<i64> {
        parse_i64(comment)
    }

    /// 字符串转f32
    pub fn parse_f32(comment: String) -> Results<f32> {
        parse_f32(comment)
    }

    /// 字符串转f64
    pub fn parse_f64(comment: String) -> Results<f64> {
        parse_f64(comment)
    }

    /// 字符串转bool
    pub fn parse_bool(comment: String) -> Results<bool> {
        parse_bool(comment)
    }

    /// 字节数组转utf8字符串
    pub fn from_utf8(data: Vec<u8>) -> Results<String> {
        from_utf8(data)
    }
}

fn sub_string(comment: String, begin: usize, end: usize) -> String {
    let mut s = String::new();
    let mut position: usize = 0;
    let chs = comment.chars();
    for ch in chs.into_iter() {
        if position >= begin && position < end {
            s.push(ch)
        }
        position += 1
    }
    s
}

/// 字符串左边补齐字符，长度为len
fn left_fit_string(mut comment: String, ch: char, len: usize) -> String {
    let mut comment_len = comment.len();
    if comment_len < len {
        while comment_len < len {
            comment = format!("{}{}", ch, comment);
            comment_len += 1
        }
    }
    comment
}

/// 字符串左边删除字符
fn left_un_fit_string(comment: String, ch: char) -> String {
    let mut s = String::new();
    let mut end = false;
    let chs = comment.chars();
    for cha in chs.into_iter() {
        if end {
            s.push(cha)
        } else {
            if cha.eq(&ch) {
                continue;
            }
            end = true;
            s.push(cha)
        }
    }
    s
}

/// 字符串右边补齐字符，长度为len
fn right_fit_string(mut comment: String, ch: char, len: usize) -> String {
    let mut comment_len = comment.len();
    if comment_len < len {
        while comment_len < len {
            comment.push(ch);
            comment_len += 1
        }
    }
    comment
}

/// 获取重复len次repeated的字符串
fn repeated_string(repeated: &str, len: usize) -> String {
    let mut res = String::new();
    let mut position = 0;
    while position < len {
        res.push_str(repeated);
        position += 1
    }
    res
}

/// 字符串转u8
fn parse_u8(comment: String) -> Results<u8> {
    match comment.parse::<u8>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u8", comment), err)),
    }
}

/// 字符串转u16
fn parse_u16(comment: String) -> Results<u16> {
    match comment.parse::<u16>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u16", comment), err)),
    }
}

/// 字符串转u32
fn parse_u32(comment: String) -> Results<u32> {
    match comment.parse::<u32>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u32", comment), err)),
    }
}

/// 字符串转u64
fn parse_u64(comment: String) -> Results<u64> {
    match comment.parse::<u64>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u64", comment), err)),
    }
}

/// 字符串转u8
fn parse_i8(comment: String) -> Results<i8> {
    match comment.parse::<i8>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u8", comment), err)),
    }
}

/// 字符串转u16
fn parse_i16(comment: String) -> Results<i16> {
    match comment.parse::<i16>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to u16", comment), err)),
    }
}

/// 字符串转i32
fn parse_i32(comment: String) -> Results<i32> {
    match comment.parse::<i32>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to i32", comment), err)),
    }
}

/// 字符串转i64
fn parse_i64(comment: String) -> Results<i64> {
    match comment.parse::<i64>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to i64", comment), err)),
    }
}

/// 字符串转f32
fn parse_f32(comment: String) -> Results<f32> {
    match comment.parse::<f32>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to f32", comment), err)),
    }
}

/// 字符串转f64
fn parse_f64(comment: String) -> Results<f64> {
    match comment.parse::<f64>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to f64", comment), err)),
    }
}

/// 字符串转bool
fn parse_bool(comment: String) -> Results<bool> {
    match comment.parse::<bool>() {
        Ok(real) => Ok(real),
        Err(err) => Err(Errs::strings(format!("{} parse to bool", comment), err)),
    }
}

fn from_utf8(data: Vec<u8>) -> Results<String> {
    match String::from_utf8(data) {
        Ok(res) => Ok(res),
        Err(err) => Err(Errs::strs("string from utf8", err)),
    }
}

#[cfg(test)]
mod test {
    use crate::strings::Strings;

    #[test]
    fn sub_string_test() {
        let s = String::from("hello world, 你好，中国！");
        println!("{:#?}", s.chars());
        println!("{}", Strings::sub(s.clone(), 0, 1));
        println!("{}", Strings::sub(s.clone(), 1, 2));
        println!("{}", Strings::sub(s.clone(), 2, 3));
        println!("{}", Strings::sub(s.clone(), 3, 4));
        println!("{}", Strings::sub(s.clone(), 5, 10));
        println!("{}", Strings::sub(s.clone(), 13, 15));
        println!("{}", Strings::sub(s.clone(), 16, 18));
    }

    #[test]
    fn zero_test() {
        let x = "hello".to_string();
        let x1 = Strings::left_fit(x.clone(), "0".parse().unwrap(), 6);
        let x2 = Strings::left_fit(x.clone(), "#".parse().unwrap(), 10);
        let x3 = Strings::left_fit(x.clone(), "@".parse().unwrap(), 11);
        let x4 = Strings::left_fit(x.clone(), "%".parse().unwrap(), 12);
        let x5 = Strings::left_fit(x.clone(), "*".parse().unwrap(), 30);
        println!("1 = {}", x1);
        println!("2 = {}", x2);
        println!("3 = {}", x3);
        println!("4 = {}", x4);
        println!("5 = {}", x5);

        println!();

        println!(
            "1 = {}",
            Strings::left_un_fit(x1.clone(), "0".parse().unwrap())
        );
        println!(
            "2 = {}",
            Strings::left_un_fit(x2.clone(), "#".parse().unwrap())
        );
        println!(
            "3 = {}",
            Strings::left_un_fit(x3.clone(), "@".parse().unwrap())
        );
        println!(
            "4 = {}",
            Strings::left_un_fit(x4.clone(), "%".parse().unwrap())
        );
        println!(
            "5 = {}",
            Strings::left_un_fit(x5.clone(), "*".parse().unwrap())
        );

        println!();

        println!(
            "1 = {}",
            Strings::right_fit(x.clone(), "0".parse().unwrap(), 6)
        );
        println!(
            "2 = {}",
            Strings::right_fit(x.clone(), "0".parse().unwrap(), 10)
        );
        println!(
            "3 = {}",
            Strings::right_fit(x.clone(), "0".parse().unwrap(), 11)
        );
        println!(
            "4 = {}",
            Strings::right_fit(x.clone(), "0".parse().unwrap(), 12)
        );
        println!(
            "5 = {}",
            Strings::right_fit(x.clone(), "0".parse().unwrap(), 13)
        );
    }

    #[test]
    fn repeated_string_test() {
        let repeated1 = "hello";
        let repeated_string1 = Strings::repeater_str(repeated1, 10);
        println!("repeated_string1 = {}", repeated_string1);
        println!();
        let repeated2 = "0";
        let repeated_string2 = Strings::repeater_str(repeated2, 1537);
        println!("repeated_string2 = {}", repeated_string2);
    }

    #[test]
    fn parse_test() {
        let i8_str = "-3";
        let i16_str = "-888";
        let i32_str = "-888999";
        let i64_str = "-999888999";
        let u8_str = "3";
        let u16_str = "888";
        let u32_str = "888999";
        let u64_str = "999888999";
        let f32_str = "888999.888";
        let f64_str = "888999.888999";
        let bool_true_str = "true";
        let bool_false_str = "false";

        println!("i8_str = {}", Strings::parse_i8_str(i8_str).unwrap());
        println!("i8     = {}", Strings::parse_i8(i8_str.to_string()).unwrap());
        println!("i16_str = {}", Strings::parse_i16_str(i16_str).unwrap());
        println!("i16     = {}", Strings::parse_i16(i16_str.to_string()).unwrap());
        println!("i32_str = {}", Strings::parse_i32_str(i32_str).unwrap());
        println!("i32     = {}", Strings::parse_i32(i32_str.to_string()).unwrap());
        println!("i64_str = {}", Strings::parse_i64_str(i64_str).unwrap());
        println!("i64     = {}", Strings::parse_i64(i64_str.to_string()).unwrap());
        println!("u8_str = {}", Strings::parse_u8_str(u8_str).unwrap());
        println!("u8     = {}", Strings::parse_u8(u8_str.to_string()).unwrap());
        println!("u16_str = {}", Strings::parse_u16_str(u16_str).unwrap());
        println!("u16     = {}", Strings::parse_u16(u16_str.to_string()).unwrap());
        println!("u32_str = {}", Strings::parse_u32_str(u32_str).unwrap());
        println!("u32     = {}", Strings::parse_u32(u32_str.to_string()).unwrap());
        println!("u64_str = {}", Strings::parse_u64_str(u64_str).unwrap());
        println!("u64     = {}", Strings::parse_u64(u64_str.to_string()).unwrap());
        println!("f32_str = {}", Strings::parse_f32_str(f32_str).unwrap());
        println!("f32     = {}", Strings::parse_f32(f32_str.to_string()).unwrap());
        println!("f64_str = {}", Strings::parse_f64_str(f64_str).unwrap());
        println!("f64     = {}", Strings::parse_f64(f64_str.to_string()).unwrap());
        println!("bool_true_str = {}", Strings::parse_bool_str(bool_true_str).unwrap());
        println!("bool_true     = {}", Strings::parse_bool(bool_true_str.to_string()).unwrap());
        println!("bool_false_str = {}", Strings::parse_bool_str(bool_false_str).unwrap());
        println!("bool_false     = {}", Strings::parse_bool(bool_false_str.to_string()).unwrap());
    }
}

