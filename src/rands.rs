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

pub struct Rand;

impl Rand {
    pub fn u8() -> u8 {
        rand::random::<u8>()
    }

    pub fn u16() -> u16 {
        rand::random::<u16>()
    }

    pub fn u32() -> u32 {
        rand::random::<u32>()
    }

    pub fn u64() -> u64 {
        rand::random::<u64>()
    }

    pub fn f32() -> f32 {
        rand::random::<f32>()
    }

    pub fn f64() -> f64 {
        rand::random::<f64>()
    }
}

#[cfg(test)]
mod rands_test {
    use rand::Rng;

    use crate::Rand;

    #[test]
    fn test_rng() {
        let mut v = vec![1, 2, 3];

        for x in v.iter_mut() {
            *x = rand::random();
            println!("x1 = {}", x)
        }

        // can be made faster by caching thread_rng

        let mut rng = rand::thread_rng();

        for x in v.iter_mut() {
            *x = rng.gen();
            println!("x2 = {}", x)
        }
    }

    #[test]
    fn test_f32() {
        println!("f32 0 = {}", Rand::f32());
        println!("f32 1 = {}", Rand::f32());
        println!("f32 2 = {}", Rand::f32());
        println!("f32 3 = {}", Rand::f32());
        println!("f32 4 = {}", Rand::f32());
        println!("f32 5 = {}", Rand::f32());
        println!("f32 6 = {}", Rand::f32());
        println!("f32 7 = {}", Rand::f32());
        println!("f32 8 = {}", Rand::f32());
        println!("f32 9 = {}", Rand::f32());
    }

    #[test]
    fn test_f64() {
        println!("f64 0 = {}", Rand::f64());
        println!("f64 1 = {}", Rand::f64());
        println!("f64 2 = {}", Rand::f64());
        println!("f64 3 = {}", Rand::f64());
        println!("f64 4 = {}", Rand::f64());
        println!("f64 5 = {}", Rand::f64());
        println!("f64 6 = {}", Rand::f64());
        println!("f64 7 = {}", Rand::f64());
        println!("f64 8 = {}", Rand::f64());
        println!("f64 9 = {}", Rand::f64());
    }

    #[test]
    fn test_u8() {
        println!("u8 0 = {}", Rand::u8());
        println!("u8 1 = {}", Rand::u8());
        println!("u8 2 = {}", Rand::u8());
        println!("u8 3 = {}", Rand::u8());
        println!("u8 4 = {}", Rand::u8());
        println!("u8 5 = {}", Rand::u8());
        println!("u8 6 = {}", Rand::u8());
        println!("u8 7 = {}", Rand::u8());
        println!("u8 8 = {}", Rand::u8());
        println!("u8 9 = {}", Rand::u8());
    }

    #[test]
    fn test_u16() {
        println!("u16 0 = {}", Rand::u16());
        println!("u16 1 = {}", Rand::u16());
        println!("u16 2 = {}", Rand::u16());
        println!("u16 3 = {}", Rand::u16());
        println!("u16 4 = {}", Rand::u16());
        println!("u16 5 = {}", Rand::u16());
        println!("u16 6 = {}", Rand::u16());
        println!("u16 7 = {}", Rand::u16());
        println!("u16 8 = {}", Rand::u16());
        println!("u16 9 = {}", Rand::u16());
    }

    #[test]
    fn test_u32() {
        println!("u32 0 = {}", Rand::u32());
        println!("u32 1 = {}", Rand::u32());
        println!("u32 2 = {}", Rand::u32());
        println!("u32 3 = {}", Rand::u32());
        println!("u32 4 = {}", Rand::u32());
        println!("u32 5 = {}", Rand::u32());
        println!("u32 6 = {}", Rand::u32());
        println!("u32 7 = {}", Rand::u32());
        println!("u32 8 = {}", Rand::u32());
        println!("u32 9 = {}", Rand::u32());
    }

    #[test]
    fn test_u64() {
        println!("u64 0 = {}", Rand::u64());
        println!("u64 1 = {}", Rand::u64());
        println!("u64 2 = {}", Rand::u64());
        println!("u64 3 = {}", Rand::u64());
        println!("u64 4 = {}", Rand::u64());
        println!("u64 5 = {}", Rand::u64());
        println!("u64 6 = {}", Rand::u64());
        println!("u64 7 = {}", Rand::u64());
        println!("u64 8 = {}", Rand::u64());
        println!("u64 9 = {}", Rand::u64());
    }
}
