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

use std::fmt::Display;

use crate::errors::{Errs, Results};

pub struct Vector;

pub trait VectorHandler<T> {
    /// 检查字节数组是否被填充，即数组中任意字节不为`0x00`
    fn is_fill(bytes: T) -> bool;

    /// 检查字节数组是否为空或都不为`0x00`
    fn is_empty(bytes: T) -> bool;
}

impl VectorHandler<Vec<u8>> for Vector {
    fn is_fill(bytes: Vec<u8>) -> bool {
        let bs_len = bytes.len();
        let mut i = 0;
        while i < bs_len {
            if bytes[i].ne(&0x00) {
                return true;
            }
            i += 1;
        }
        false
    }

    fn is_empty(bytes: Vec<u8>) -> bool {
        let bs_len = bytes.len();
        let mut i = 0;
        while i < bs_len {
            if bytes[i].ne(&0x00) {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl VectorHandler<&[u8]> for Vector {
    fn is_fill(bytes: &[u8]) -> bool {
        let bs_len = bytes.len();
        let mut i = 0;
        while i < bs_len {
            if bytes[i].ne(&0x00) {
                return true;
            }
            i += 1;
        }
        false
    }

    fn is_empty(bytes: &[u8]) -> bool {
        let bs_len = bytes.len();
        let mut i = 0;
        while i < bs_len {
            if bytes[i].ne(&0x00) {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl Vector {
    /// 变更数组内容
    ///
    /// * source 原始数组
    /// * target 变更内容
    /// * start 起始下标
    pub fn modify<T: Clone>(source: Vec<T>, target: Vec<T>, start: usize) -> Vec<T> {
        vector_modify(source, target, start)
    }

    /// 截取数组
    ///
    /// * source 原始数组
    /// * start 截取起始下标
    /// * end 截取终止下标
    pub fn sub<T: Clone>(source: Vec<T>, start: usize, end: usize) -> Results<Vec<T>> {
        vector_sub(source, start, end)
    }

    /// 截取数组
    ///
    /// * source 原始数组
    /// * start 截取起始下标
    /// * end 截取终止下标
    pub fn sub_u8<T: Clone>(source: &[T], start: usize, end: usize) -> Results<Vec<T>> {
        vector_sub_4_u8(source, start, end)
    }

    /// 截取数组
    ///
    /// * source 原始数组
    /// * start 截取起始下标
    /// * 持续读取个数
    pub fn sub_last<T: Clone>(source: Vec<T>, start: usize, last: usize) -> Results<Vec<T>> {
        vector_sub(source, start, start + last)
    }

    /// 截取数组
    ///
    /// * source 原始数组
    /// * start 截取起始下标
    /// * 持续读取个数
    pub fn sub_last_u8<T: Clone>(source: &[T], start: usize, last: usize) -> Results<Vec<T>> {
        vector_sub_4_u8(source, start, start + last)
    }

    /// 拼接数组
    pub fn append<T: Clone>(source: Vec<T>, target: Vec<T>) -> Vec<T> {
        vector_append(source, target)
    }

    /// 拼接数组
    pub fn appends<T: Clone>(source: Vec<T>, targets: Vec<Vec<T>>) -> Vec<T> {
        vector_appends(source, targets)
    }

    /// 拼接数组
    pub fn appender<T: Clone>(targets: Vec<Vec<T>>) -> Vec<T> {
        vector_appender(targets)
    }

    /// 从可被`eq`整除的bytes长度的字节数组中查找最后不为0的`eq`个字节组成新的数组
    pub fn find_last_eq_bytes(bytes: Vec<u8>, eq: usize) -> Results<Vec<u8>> {
        vector_find_last_eq_bytes(bytes, eq)
    }

    /// 从可被`eq`整除的bytes长度的字节数组中查找所有与`eq`长度相同的不为0的字节数组集合
    pub fn find_eq_vec_bytes(bytes: Vec<u8>, eq: usize) -> Results<Vec<Vec<u8>>> {
        vector_find_eq_vec_bytes(bytes, eq)
    }

    /// 创建长度为len且字节均为0x00的字节数组
    pub fn create_empty_bytes(len: usize) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(len);
        let mut position = 0;
        while position < len {
            res.push(0x00);
            position += 1
        }
        res
    }

    /// 创建长度为len且内容为空的数组
    pub fn create_empty<T>(len: usize) -> Vec<T> {
        Vec::with_capacity(len)
    }

    /// 横向打印数组
    pub fn print<T>(source: Vec<T>)
        where
            T: Clone,
            T: Display,
    {
        vector_print(source)
    }
}

/// 变更数组内容
///
/// source 原始数组
///
/// target 变更内容
///
/// start 起始下标
fn vector_modify<T: Clone>(mut source: Vec<T>, target: Vec<T>, mut start: usize) -> Vec<T> {
    let len = target.len();
    let mut position = 0;
    while position < len {
        source.remove(start);
        source.insert(start, target.get(position).unwrap().clone());
        start += 1;
        position += 1
    }
    source
}

/// 截取数组
///
/// source 原始数组
///
/// start 截取起始下标
///
/// end 截取终止下标，如果为0，则取start之后所有数据
fn vector_sub<T: Clone>(source: Vec<T>, start: usize, end: usize) -> Results<Vec<T>> {
    let source_len = source.len();
    if source_len < end {
        Err(Errs::str("source array type out of bounds"))
    } else {
        let mut s1 = source.to_vec();
        let mut s2 = s1.split_off(start);
        if end > 0 {
            let _x = s2.split_off(end - start);
        }
        Ok(s2)
    }
}

/// 截取数组
///
/// source 原始数组
///
/// start 截取起始下标
///
/// end 截取终止下标，如果为0，则取start之后所有数据
fn vector_sub_4_u8<T: Clone>(source: &[T], start: usize, end: usize) -> Results<Vec<T>> {
    let source_len = source.len();
    if source_len >= end {
        let mut s1 = source.to_vec();
        let mut s2 = s1.split_off(start);
        if end > 0 {
            let _x = s2.split_off(end - start);
        }
        Ok(s2)
    } else {
        Err(Errs::str("source array type out of bounds"))
    }
}

/// 从可被`eq`整除的bytes长度的字节数组中查找最后不为0的`eq`个字节组成新的数组
fn vector_find_last_eq_bytes(bytes: Vec<u8>, eq: usize) -> Results<Vec<u8>> {
    let mut res: Vec<u8> = vec![];
    let mut temp: Vec<u8> = vec![];
    let mut position = 0;
    let mut valid = false;
    for b in bytes {
        if position < eq {
            if valid || b > 0x00 {
                valid = true;
            }
            temp.push(b);
            position += 1
        } else {
            if temp.len().ne(&eq) {
                return Err(Errs::str("temp length out of 8"));
            }
            if valid {
                res = temp.to_vec();
            }
            temp.clear();
            position = 0;
            if b > 0x00 {
                valid = true;
            } else {
                valid = false;
            }
            temp.push(b);
            position += 1
        }
    }
    Ok(res)
}

/// 从可被`eq`整除的bytes长度的字节数组中查找所有与`eq`长度相同的不为0的字节数组集合
fn vector_find_eq_vec_bytes(mut bytes: Vec<u8>, eq: usize) -> Results<Vec<Vec<u8>>> {
    if bytes.len() % eq != 0 {
        return Err(Errs::string(format!("bytes length can not mod by {}", eq)));
    }
    // 此步确保能够遍历完成最后一组
    bytes.push(0x00);
    let mut res: Vec<Vec<u8>> = vec![];
    let mut temp: Vec<u8> = vec![];
    let mut position = 0;
    let mut valid = false;
    for b in bytes {
        if position < eq {
            if valid || b > 0x00 {
                valid = true;
            }
            temp.push(b);
            position += 1
        } else {
            if temp.len().ne(&eq) {
                return Err(Errs::str("temp length out of 8"));
            }
            if valid {
                res.push(temp.to_vec())
            }
            temp.clear();
            position = 0;
            if b > 0x00 {
                valid = true;
            } else {
                valid = false;
            }
            temp.push(b);
            position += 1
        }
    }
    Ok(res)
}

// /// 创建长度为len且字节均为0x00的字节数组
// fn create_empty_bytes(len: usize) -> Vec<u8> {
//     let mut res: Vec<u8> = Vec::with_capacity(len);
//     let mut position = 0;
//     while position < len {
//         res.push(0x00);
//         position += 1
//     }
//     res
// }

/// 拼接数组
fn vector_append<T: Clone>(source: Vec<T>, target: Vec<T>) -> Vec<T> {
    let mut res = vec![];
    for t in source {
        res.push(t);
    }
    for t in target {
        res.push(t);
    }
    res
}

/// 拼接数组
fn vector_appends<T: Clone>(source: Vec<T>, targets: Vec<Vec<T>>) -> Vec<T> {
    let mut res = vec![];
    for t in source {
        res.push(t);
    }
    for target in targets {
        for t in target {
            res.push(t);
        }
    }
    res
}

/// 拼接数组
fn vector_appender<T: Clone>(targets: Vec<Vec<T>>) -> Vec<T> {
    let mut res = vec![];
    for target in targets {
        for t in target {
            res.push(t);
        }
    }
    res
}

fn vector_print<T>(source: Vec<T>)
    where
        T: Clone,
        T: Display,
{
    for v in source {
        print!("{} ", v)
    }
    println!()
}

#[cfg(test)]
mod vectors_test {
    use crate::vectors::Vector;

    #[test]
    fn modify_test() {
        let x: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10];
        let start = 3;
        let y: Vec<u8> = vec![0x20, 0x21, 0x22, 0x23, 0x24];
        let z = Vector::modify(x.clone(), y, start);
        println!("x = {:#?}\nz = {:#?}", x, z)
    }

    #[test]
    fn sub_test() {
        let vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        println!("sub = {:#?}", Vector::sub(vec.clone(), 2, 5).unwrap());
        println!("sub = {:#?}", Vector::sub(vec.clone(), 2, 0).unwrap());
        println!("sub = {:#?}", Vector::sub_last(vec, 2, 5).unwrap());

        let x: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10];
        println!("sub = {:#?}", Vector::sub(x.clone(), 2, 5).unwrap());
        println!("x = {:#?}", x);
    }

    #[test]
    fn find_last_eq_bytes_test() {
        let mut a: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut b = Vector::create_empty_bytes(8);
        let mut c = vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10];
        let mut d = Vector::create_empty_bytes(8);
        let mut e = vec![0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x08, 0x10];
        let mut f = Vector::create_empty_bytes(8);
        a.append(&mut b);
        a.append(&mut c);
        a.append(&mut d);
        a.append(&mut e);
        a.append(&mut f);
        println!("a = {:#?}", a);
        let g = Vector::find_last_eq_bytes(a, 8);
        println!("g = {:#?}", g);
    }

    #[test]
    fn find_eq_vec_bytes_test() {
        let mut a: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut b = Vector::create_empty_bytes(8);
        let mut c = vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10];
        let mut d = Vector::create_empty_bytes(8);
        let mut e = vec![0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x08, 0x10];
        let mut f = Vector::create_empty_bytes(8);
        a.append(&mut b);
        a.append(&mut c);
        a.append(&mut d);
        a.append(&mut e);
        a.append(&mut f);
        println!("a = {:#?}", a);
        let g = Vector::find_eq_vec_bytes(a, 8);
        println!("g = {:#?}", g);
    }

    #[test]
    fn vec_append() {
        let a = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let b = vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10];
        let z = Vector::append(a, b);
        Vector::print(z)
    }

    #[test]
    fn vec_appends() {
        let a = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let b = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let c = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let z = Vector::appends(a, vec![b, c]);
        Vector::print(z)
    }

    #[test]
    fn vec_appender() {
        let a = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let b = vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
        let c = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let z = Vector::appender(vec![a, b, c]);
        Vector::print(z)
    }
}
