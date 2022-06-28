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

use std::fs::read_to_string;
use std::path::Path;

use libsm::sm2::ecc::Point;
use libsm::sm2::signature::{SigCtx, Signature};
use num_bigint::BigUint;

use crate::cryptos::{Decoder, Encoder};
use crate::cryptos::base64::Base64;
use crate::cryptos::Hex;
use crate::errors::{Errs, Results};
use crate::io::file::FilerWriter;
use crate::io::file::Filer;

/// 字节数组与字符串通过Base64转换
pub struct SM2 {
    ctx: SigCtx,
    sk: BigUint,
    pk: Point,
}

pub trait SkNew {
    /// 生成非对称加密私钥，返回sk字节数组
    fn generate() -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    fn generate_hex() -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    fn generate_base64() -> Results<String>;
}

pub trait SkNewStore {
    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;
}

pub trait SKNew {
    /// 生成非对称加密公私钥，返回sk、pk字节数组
    fn generate() -> Results<(Vec<u8>, Vec<u8>)>;

    /// 生成非对称加密公私钥，返回sk、pk字符串
    fn generate_hex() -> Results<(String, String)>;

    /// 生成非对称加密公私钥，返回sk、pk字符串
    fn generate_base64() -> Results<(String, String)>;
}

pub trait SKNewStore {
    /// 生成非对称加密公私钥，返回sk、pk字节数组
    ///
    /// 并将生成的公私钥存储在sk、pk指定文件中
    fn generate<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P)
                                -> Results<(Vec<u8>, Vec<u8>)>;

    /// 生成非对称加密公私钥，返回sk、pk字符串
    ///
    /// 并将生成的公私钥存储在sk、pk指定文件中
    fn generate_hex<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<(String, String)>;

    /// 生成非对称加密公私钥，返回sk、pk字符串
    ///
    /// 并将生成的公私钥存储在sk、pk指定文件中
    fn generate_base64<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<(String, String)>;
}

pub trait SKPk {
    /// 根据私钥生成公钥
    fn generate_pk(sk: Vec<u8>) -> Results<Vec<u8>>;

    /// 根据私钥hex字符串生成公钥
    fn generate_pk_by_hex(sk: String) -> Results<Vec<u8>>;

    /// 根据私钥base64字符串生成公钥
    fn generate_pk_by_base64(sk: String) -> Results<Vec<u8>>;

    /// 根据私钥hex字符串文件生成公钥
    fn generate_pk_by_hex_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;

    /// 根据私钥base64字符串文件生成公钥
    fn generate_pk_by_base64_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;
}

pub trait SKStoreKey<T> {
    /// 将公/私钥存储在指定文件中
    fn store<P: AsRef<Path>>(key: T, key_filepath: P) -> Results<()>;

    /// 将公/私钥存储在指定文件中
    fn store_hex<P: AsRef<Path>>(key: T, key_filepath: P) -> Results<()>;

    /// 将公/私钥存储在指定文件中
    fn store_base64<P: AsRef<Path>>(key: T, key_filepath: P) -> Results<()>;
}

pub trait SKStore {
    /// 将公/私钥存储在指定文件中
    fn store<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()>;
}

pub trait SKLoadKey {
    /// 从指定文件中读取公/私钥
    fn load<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<SM2>;

    /// 从指定文件中读取公/私钥
    fn load_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<Vec<u8>>;

    /// 从指定文件中读取公/私钥
    fn load_string_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<String>;
}

pub trait SKSign<M, N> {
    /// 签名msg，返回签名结果字节数组
    ///
    /// msg 待签名数据
    ///
    /// sk、pk 签名使用公私钥
    fn sign(msg: M, sk: N, pk: N) -> Results<Vec<u8>>;

    /// 签名msg，返回签名结果字符串
    ///
    /// msg 待签名数据
    ///
    /// sk、pk 签名使用公私钥
    fn sign_hex(msg: M, sk: N, pk: N) -> Results<String>;

    /// 签名msg，返回签名结果字符串
    ///
    /// msg 待签名数据
    ///
    /// sk、pk 签名使用公私钥
    fn sign_base64(msg: M, sk: N, pk: N) -> Results<String>;
}

pub trait SKSignPath<T> {
    /// 签名msg，返回签名结果字节数组
    ///
    /// msg 待签名数据
    ///
    /// sk、pk 签名使用公私钥文件
    fn sign<P: AsRef<Path>>(msg: T, sk_filepath: P, pk_filepath: P) -> Results<Vec<u8>>;

    /// 签名msg，返回签名结果字符串
    ///
    /// msg 待签名数据
    ///
    /// sk、pk 签名使用公私钥文件
    fn sign_base64<P: AsRef<Path>>(msg: T, sk_filepath: P, pk_filepath: P) -> Results<String>;
}

pub trait SKVerify<M, N, O> {
    /// 验签msg
    fn verify(msg: M, pk: N, der: O) -> Results<bool>;
}

pub trait SKVerifyPath<M, N> {
    /// 验签msg
    fn verify<P: AsRef<Path>>(msg: M, sk_filepath: P, der: N) -> Results<bool>;
}

impl SM2 {
    /// 生成非对称加密公私钥
    pub fn new() -> Results<SM2> {
        let (ctx, pk, sk) = new_keypair()?;
        Ok(SM2 { ctx, sk, pk })
    }

    pub fn new_pk(&self) -> Results<Vec<u8>> {
        match self.ctx.pk_from_sk(&self.sk) {
            Ok(p) => match self.ctx.serialize_pubkey(&p, true) {
                Ok(src) => Ok(src),
                Err(err) => Err(Errs::strs("new sm2 in serialize_pubkey failed!", err)),
            },
            Err(err) => Err(Errs::strs("new sm2 pk_from_sk failed!", err)),
        }
    }
    pub fn sk_bytes(&self) -> Results<Vec<u8>> {
        match self.ctx.serialize_seckey(&self.sk) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm2 sk_bytes failed!", err)),
        }
    }

    pub fn pk_bytes(&self) -> Results<Vec<u8>> {
        match self.ctx.serialize_pubkey(&self.pk, true) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm2 pk_bytes failed!", err)),
        }
    }

    fn signature(&self, msg: &[u8], pk_point: &Point) -> Results<Signature> {
        match self.ctx.sign(msg, &self.sk, pk_point) {
            Ok(src) => Ok(src),
            Err(err) => Err(Errs::strs("sm2 sig failed!", err)),
        }
    }

    pub fn sig(&self, msg: &[u8]) -> Results<Vec<u8>> {
        let sig = self.signature(msg, &self.pk)?;
        Ok(sig.der_encode())
    }

    pub fn sig_hex(&self, msg: &[u8]) -> Results<String> {
        let sig = self.signature(msg, &self.pk)?;
        Ok(Hex::encode(sig.der_encode()))
    }

    pub fn sig_base64(&self, msg: &[u8]) -> Results<String> {
        let sig = self.signature(msg, &self.pk)?;
        Ok(Base64::encode(sig.der_encode()))
    }

    pub fn sig_pk(&self, msg: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
        let pk_point: Point;
        match self.ctx.load_pubkey(pk) {
            Ok(pp) => pk_point = pp,
            Err(err) => return Err(Errs::string(format!("load pub key error! {:#?}", err))),
        }
        let sig = self.signature(msg, &pk_point)?;
        Ok(sig.der_encode())
    }

    pub fn verifies(&self, msg: &[u8], der: &[u8]) -> Results<bool> {
        match Signature::der_decode(der) {
            Ok(sig) => match self.ctx.verify(msg, &self.pk, &sig) {
                Ok(src) => Ok(src),
                Err(err) => return Err(Errs::strs("sm2 verifies verify failed!", err)),
            },
            Err(err) => return Err(Errs::strs("sm2 verifies der decode", err)),
        }
    }

    pub fn verifies_pk(&self, msg: &[u8], der: &[u8], pk: &[u8]) -> Results<bool> {
        match self.ctx.load_pubkey(pk) {
            Ok(pk_point) => match Signature::der_decode(der) {
                Ok(sig) => match self.ctx.verify(msg, &pk_point, &sig) {
                    Ok(src) => Ok(src),
                    Err(err) => return Err(Errs::strs("der decode", err)),
                },
                Err(err) => return Err(Errs::strs("der decode", err)),
            },
            Err(err) => return Err(Errs::string(format!("load pub key error! {:#?}", err))),
        }
    }
}

////////// sm generate start //////////

impl SkNew for SM2 {
    fn generate() -> Results<Vec<u8>> {
        generate_sk()
    }

    fn generate_hex() -> Results<String> {
        Ok(Hex::encode(generate_sk()?))
    }

    fn generate_base64() -> Results<String> {
        Ok(Base64::encode(generate_sk()?))
    }
}

impl SkNewStore for SM2 {
    fn generate<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_sk_in_file(sk_filepath)
    }

    fn generate_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_sk_hex_in_file(sk_filepath)
    }

    fn generate_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_sk_base64_in_file(sk_filepath)
    }
}

impl SKNew for SM2 {
    fn generate() -> Results<(Vec<u8>, Vec<u8>)> {
        generate()
    }

    fn generate_hex() -> Results<(String, String)> {
        generate_hex()
    }

    fn generate_base64() -> Results<(String, String)> {
        generate_base64()
    }
}

impl SKNewStore for SM2 {
    fn generate<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<(Vec<u8>, Vec<u8>)> {
        generate_in_file(sk_filepath, pk_filepath)
    }

    fn generate_hex<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<(String, String)> {
        generate_hex_in_file(sk_filepath, pk_filepath)
    }

    fn generate_base64<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<(String, String)> {
        generate_base64_in_file(sk_filepath, pk_filepath)
    }
}

////////// sm generate end //////////

////////// sm generate pk from sk start //////////
impl SKPk for SM2 {
    fn generate_pk(sk: Vec<u8>) -> Results<Vec<u8>> {
        generate_pk_from_sk(sk)
    }

    fn generate_pk_by_hex(sk: String) -> Results<Vec<u8>> {
        generate_pk_from_sk_hex(sk)
    }

    fn generate_pk_by_base64(sk: String) -> Results<Vec<u8>> {
        generate_pk_from_sk_base64(sk)
    }

    fn generate_pk_by_hex_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_from_sk_hex_file(sk_filepath)
    }

    fn generate_pk_by_base64_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_from_sk_base64_file(sk_filepath)
    }
}

////////// sm generate pk from sk end //////////

////////// sm store/load start //////////

impl SKStoreKey<&[u8]> for SM2 {
    fn store<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
        stores(key, key_filepath)
    }

    fn store_hex<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
        store_hex_key(key, key_filepath)
    }

    fn store_base64<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
        store_base64_key(key, key_filepath)
    }
}

impl SKStoreKey<Vec<u8>> for SM2 {
    fn store<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
        stores(key.as_slice(), key_filepath)
    }

    fn store_hex<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
        store_hex_bytes_key(key, key_filepath)
    }

    fn store_base64<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
        store_base64_bytes_key(key, key_filepath)
    }
}

impl SKStore for SM2 {
    fn store<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()> {
        store_key(Base64::encode(self.sk_bytes().unwrap()), sk_filepath)?;
        store_key(Base64::encode(self.pk_bytes().unwrap()), pk_filepath)
    }
}

impl SKLoadKey for SM2 {
    fn load<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<SM2> {
        let sk_bytes = load_key_from_file(sk_filepath)?;
        let pk_bytes = load_key_from_file(pk_filepath)?;
        let ctx = SigCtx::new();
        match ctx.load_pubkey(pk_bytes.as_slice()) {
            Ok(pk) => match ctx.load_seckey(sk_bytes.as_slice()) {
                Ok(sk) => Ok(SM2 { ctx, sk, pk }),
                Err(err) => return Err(Errs::string(format!("load pub key error! {:#?}", err))),
            },
            Err(err) => return Err(Errs::string(format!("load pub key error! {:#?}", err))),
        }
    }

    fn load_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<Vec<u8>> {
        load_key_from_file(key_filepath)
    }

    fn load_string_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<String> {
        load_key_string_from_file(key_filepath)
    }
}

////////// sm store/load end //////////

////////// sm sign start //////////

impl SKSign<&[u8], &[u8]> for SM2 {
    fn sign(msg: &[u8], sk: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
        sign(msg, sk, pk)
    }

    fn sign_hex(msg: &[u8], sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Hex::encode(sign(msg, sk, pk)?))
    }

    fn sign_base64(msg: &[u8], sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Base64::encode(sign(msg, sk, pk)?))
    }
}

impl SKSign<&[u8], Vec<u8>> for SM2 {
    fn sign(msg: &[u8], sk: Vec<u8>, pk: Vec<u8>) -> Results<Vec<u8>> {
        sign(msg, sk.as_slice(), pk.as_slice())
    }

    fn sign_hex(msg: &[u8], sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Hex::encode(sign(msg, sk.as_slice(), pk.as_slice())?))
    }

    fn sign_base64(msg: &[u8], sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Base64::encode(sign(msg, sk.as_slice(), pk.as_slice())?))
    }
}

impl SKSign<Vec<u8>, Vec<u8>> for SM2 {
    fn sign(msg: Vec<u8>, sk: Vec<u8>, pk: Vec<u8>) -> Results<Vec<u8>> {
        sign(msg.as_slice(), sk.as_slice(), pk.as_slice())
    }

    fn sign_hex(msg: Vec<u8>, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_slice(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }

    fn sign_base64(msg: Vec<u8>, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_slice(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }
}

impl SKSign<String, Vec<u8>> for SM2 {
    fn sign(msg: String, sk: Vec<u8>, pk: Vec<u8>) -> Results<Vec<u8>> {
        sign(msg.as_bytes(), sk.as_slice(), pk.as_slice())
    }

    fn sign_hex(msg: String, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }

    fn sign_base64(msg: String, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }
}

impl SKSign<&str, Vec<u8>> for SM2 {
    fn sign(msg: &str, sk: Vec<u8>, pk: Vec<u8>) -> Results<Vec<u8>> {
        sign(msg.as_bytes(), sk.as_slice(), pk.as_slice())
    }

    fn sign_hex(msg: &str, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }

    fn sign_base64(msg: &str, sk: Vec<u8>, pk: Vec<u8>) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            sk.as_slice(),
            pk.as_slice(),
        )?))
    }
}

impl SKSign<Vec<u8>, &[u8]> for SM2 {
    fn sign(msg: Vec<u8>, sk: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
        sign(msg.as_slice(), sk, pk)
    }

    fn sign_hex(msg: Vec<u8>, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Hex::encode(sign(msg.as_slice(), sk, pk)?))
    }

    fn sign_base64(msg: Vec<u8>, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Base64::encode(sign(msg.as_slice(), sk, pk)?))
    }
}

impl SKSign<String, &[u8]> for SM2 {
    fn sign(msg: String, sk: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
        sign(msg.as_bytes(), sk, pk)
    }

    fn sign_hex(msg: String, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Hex::encode(sign(msg.as_bytes(), sk, pk)?))
    }

    fn sign_base64(msg: String, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Base64::encode(sign(msg.as_bytes(), sk, pk)?))
    }
}

impl SKSign<&str, &[u8]> for SM2 {
    fn sign(msg: &str, sk: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
        sign(msg.as_bytes(), sk, pk)
    }

    fn sign_hex(msg: &str, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Hex::encode(sign(msg.as_bytes(), sk, pk)?))
    }

    fn sign_base64(msg: &str, sk: &[u8], pk: &[u8]) -> Results<String> {
        Ok(Base64::encode(sign(msg.as_bytes(), sk, pk)?))
    }
}

impl SKSign<&[u8], String> for SM2 {
    fn sign(msg: &[u8], sk: String, pk: String) -> Results<Vec<u8>> {
        sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: &[u8], sk: String, pk: String) -> Results<String> {
        Ok(Hex::encode(sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: &[u8], sk: String, pk: String) -> Results<String> {
        Ok(Base64::encode(sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<Vec<u8>, String> for SM2 {
    fn sign(msg: Vec<u8>, sk: String, pk: String) -> Results<Vec<u8>> {
        sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: Vec<u8>, sk: String, pk: String) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: Vec<u8>, sk: String, pk: String) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<String, String> for SM2 {
    fn sign(msg: String, sk: String, pk: String) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: String, sk: String, pk: String) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: String, sk: String, pk: String) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<&str, String> for SM2 {
    fn sign(msg: &str, sk: String, pk: String) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: &str, sk: String, pk: String) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: &str, sk: String, pk: String) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<&[u8], &str> for SM2 {
    fn sign(msg: &[u8], sk: &str, pk: &str) -> Results<Vec<u8>> {
        sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: &[u8], sk: &str, pk: &str) -> Results<String> {
        Ok(Hex::encode(sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: &[u8], sk: &str, pk: &str) -> Results<String> {
        Ok(Base64::encode(sign(
            msg,
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<Vec<u8>, &str> for SM2 {
    fn sign(msg: Vec<u8>, sk: &str, pk: &str) -> Results<Vec<u8>> {
        sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: Vec<u8>, sk: &str, pk: &str) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: Vec<u8>, sk: &str, pk: &str) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_slice(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<String, &str> for SM2 {
    fn sign(msg: String, sk: &str, pk: &str) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: String, sk: &str, pk: &str) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: String, sk: &str, pk: &str) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSign<&str, &str> for SM2 {
    fn sign(msg: &str, sk: &str, pk: &str) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )
    }

    fn sign_hex(msg: &str, sk: &str, pk: &str) -> Results<String> {
        Ok(Hex::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }

    fn sign_base64(msg: &str, sk: &str, pk: &str) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            Base64::decode(sk)?.as_slice(),
            Base64::decode(pk)?.as_slice(),
        )?))
    }
}

impl SKSignPath<&[u8]> for SM2 {
    fn sign<P: AsRef<Path>>(msg: &[u8], sk_filepath: P, pk_filepath: P) -> Results<Vec<u8>> {
        sign(
            msg,
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )
    }

    fn sign_base64<P: AsRef<Path>>(
        msg: &[u8],
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<String> {
        Ok(Base64::encode(sign(
            msg,
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )?))
    }
}

impl SKSignPath<Vec<u8>> for SM2 {
    fn sign<P: AsRef<Path>>(msg: Vec<u8>, sk_filepath: P, pk_filepath: P) -> Results<Vec<u8>> {
        sign(
            msg.as_slice(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )
    }

    fn sign_base64<P: AsRef<Path>>(
        msg: Vec<u8>,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_slice(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )?))
    }
}

impl SKSignPath<String> for SM2 {
    fn sign<P: AsRef<Path>>(msg: String, sk_filepath: P, pk_filepath: P) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )
    }

    fn sign_base64<P: AsRef<Path>>(
        msg: String,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )?))
    }
}

impl SKSignPath<&str> for SM2 {
    fn sign<P: AsRef<Path>>(msg: &str, sk_filepath: P, pk_filepath: P) -> Results<Vec<u8>> {
        sign(
            msg.as_bytes(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )
    }

    fn sign_base64<P: AsRef<Path>>(
        msg: &str,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<String> {
        Ok(Base64::encode(sign(
            msg.as_bytes(),
            load_key_from_file(sk_filepath)?.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
        )?))
    }
}

////////// sm sign end //////////

////////// sm verify start //////////

impl SKVerify<&[u8], &[u8], &[u8]> for SM2 {
    fn verify(msg: &[u8], pk: &[u8], der: &[u8]) -> Results<bool> {
        verify(msg, pk, der)
    }
}

impl SKVerify<&[u8], &[u8], Vec<u8>> for SM2 {
    fn verify(msg: &[u8], pk: &[u8], der: Vec<u8>) -> Results<bool> {
        verify(msg, pk, der.as_slice())
    }
}

impl SKVerify<&[u8], &[u8], String> for SM2 {
    fn verify(msg: &[u8], pk: &[u8], der: String) -> Results<bool> {
        verify(msg, pk, Base64::decode(der)?.as_slice())
    }
}

impl SKVerify<&[u8], &[u8], &str> for SM2 {
    fn verify(msg: &[u8], pk: &[u8], der: &str) -> Results<bool> {
        verify(msg, pk, Base64::decode(der.to_string())?.as_slice())
    }
}

impl SKVerify<&[u8], Vec<u8>, &[u8]> for SM2 {
    fn verify(msg: &[u8], pk: Vec<u8>, der: &[u8]) -> Results<bool> {
        verify(msg, pk.as_slice(), der)
    }
}

impl SKVerify<&[u8], Vec<u8>, Vec<u8>> for SM2 {
    fn verify(msg: &[u8], pk: Vec<u8>, der: Vec<u8>) -> Results<bool> {
        verify(msg, pk.as_slice(), der.as_slice())
    }
}

impl SKVerify<&[u8], Vec<u8>, String> for SM2 {
    fn verify(msg: &[u8], pk: Vec<u8>, der: String) -> Results<bool> {
        verify(msg, pk.as_slice(), Base64::decode(der)?.as_slice())
    }
}

impl SKVerify<&[u8], Vec<u8>, &str> for SM2 {
    fn verify(msg: &[u8], pk: Vec<u8>, der: &str) -> Results<bool> {
        verify(
            msg,
            pk.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&[u8], String, &[u8]> for SM2 {
    fn verify(msg: &[u8], pk: String, der: &[u8]) -> Results<bool> {
        verify(msg, &Base64::decode(pk)?.as_slice(), der)
    }
}

impl SKVerify<&[u8], String, Vec<u8>> for SM2 {
    fn verify(msg: &[u8], pk: String, der: Vec<u8>) -> Results<bool> {
        verify(msg, &Base64::decode(pk)?.as_slice(), der.as_slice())
    }
}

impl SKVerify<&[u8], String, String> for SM2 {
    fn verify(msg: &[u8], pk: String, der: String) -> Results<bool> {
        verify(
            msg,
            &Base64::decode(pk)?.as_slice(),
            &Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<&[u8], String, &str> for SM2 {
    fn verify(msg: &[u8], pk: String, der: &str) -> Results<bool> {
        verify(
            msg,
            &Base64::decode(pk)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&[u8], &str, &[u8]> for SM2 {
    fn verify(msg: &[u8], pk: &str, der: &[u8]) -> Results<bool> {
        verify(msg, &Base64::decode(pk.to_string())?.as_slice(), der)
    }
}

impl SKVerify<&[u8], &str, Vec<u8>> for SM2 {
    fn verify(msg: &[u8], pk: &str, der: Vec<u8>) -> Results<bool> {
        verify(
            msg,
            &Base64::decode(pk.to_string())?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<&[u8], &str, String> for SM2 {
    fn verify(msg: &[u8], pk: &str, der: String) -> Results<bool> {
        verify(
            msg,
            &Base64::decode(pk.to_string())?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<&[u8], &str, &str> for SM2 {
    fn verify(msg: &[u8], pk: &str, der: &str) -> Results<bool> {
        verify(
            msg,
            &Base64::decode(pk.to_string())?.as_slice(),
            &Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, &[u8], &[u8]> for SM2 {
    fn verify(msg: Vec<u8>, pk: &[u8], der: &[u8]) -> Results<bool> {
        verify(msg.as_slice(), pk, der)
    }
}

impl SKVerify<Vec<u8>, &[u8], Vec<u8>> for SM2 {
    fn verify(msg: Vec<u8>, pk: &[u8], der: Vec<u8>) -> Results<bool> {
        verify(msg.as_slice(), pk, der.as_slice())
    }
}

impl SKVerify<Vec<u8>, &[u8], String> for SM2 {
    fn verify(msg: Vec<u8>, pk: &[u8], der: String) -> Results<bool> {
        verify(msg.as_slice(), pk, Base64::decode(der)?.as_slice())
    }
}

impl SKVerify<Vec<u8>, &[u8], &str> for SM2 {
    fn verify(msg: Vec<u8>, pk: &[u8], der: &str) -> Results<bool> {
        verify(
            msg.as_slice(),
            pk,
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, Vec<u8>, &[u8]> for SM2 {
    fn verify(msg: Vec<u8>, pk: Vec<u8>, der: &[u8]) -> Results<bool> {
        verify(msg.as_slice(), pk.as_slice(), der)
    }
}

impl SKVerify<Vec<u8>, Vec<u8>, Vec<u8>> for SM2 {
    fn verify(msg: Vec<u8>, pk: Vec<u8>, der: Vec<u8>) -> Results<bool> {
        verify(msg.as_slice(), pk.as_slice(), der.as_slice())
    }
}

impl SKVerify<Vec<u8>, Vec<u8>, String> for SM2 {
    fn verify(msg: Vec<u8>, pk: Vec<u8>, der: String) -> Results<bool> {
        verify(
            msg.as_slice(),
            pk.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, Vec<u8>, &str> for SM2 {
    fn verify(msg: Vec<u8>, pk: Vec<u8>, der: &str) -> Results<bool> {
        verify(
            msg.as_slice(),
            pk.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, String, &[u8]> for SM2 {
    fn verify(msg: Vec<u8>, pk: String, der: &[u8]) -> Results<bool> {
        verify(msg.as_slice(), &Base64::decode(pk)?.as_slice(), der)
    }
}

impl SKVerify<Vec<u8>, String, Vec<u8>> for SM2 {
    fn verify(msg: Vec<u8>, pk: String, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, String, String> for SM2 {
    fn verify(msg: Vec<u8>, pk: String, der: String) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk)?.as_slice(),
            &Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, String, &str> for SM2 {
    fn verify(msg: Vec<u8>, pk: String, der: &str) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, &str, &[u8]> for SM2 {
    fn verify(msg: Vec<u8>, pk: &str, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der,
        )
    }
}

impl SKVerify<Vec<u8>, &str, Vec<u8>> for SM2 {
    fn verify(msg: Vec<u8>, pk: &str, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, &str, String> for SM2 {
    fn verify(msg: Vec<u8>, pk: &str, der: String) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk.to_string())?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<Vec<u8>, &str, &str> for SM2 {
    fn verify(msg: Vec<u8>, pk: &str, der: &str) -> Results<bool> {
        verify(
            msg.as_slice(),
            &Base64::decode(pk.to_string())?.as_slice(),
            &Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<String, &[u8], &[u8]> for SM2 {
    fn verify(msg: String, pk: &[u8], der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), pk, der)
    }
}

impl SKVerify<String, &[u8], Vec<u8>> for SM2 {
    fn verify(msg: String, pk: &[u8], der: Vec<u8>) -> Results<bool> {
        verify(msg.as_bytes(), pk, der.as_slice())
    }
}

impl SKVerify<String, &[u8], String> for SM2 {
    fn verify(msg: String, pk: &[u8], der: String) -> Results<bool> {
        verify(msg.as_bytes(), pk, Base64::decode(der)?.as_slice())
    }
}

impl SKVerify<String, &[u8], &str> for SM2 {
    fn verify(msg: String, pk: &[u8], der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk,
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<String, Vec<u8>, &[u8]> for SM2 {
    fn verify(msg: String, pk: Vec<u8>, der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), pk.as_slice(), der)
    }
}

impl SKVerify<String, Vec<u8>, Vec<u8>> for SM2 {
    fn verify(msg: String, pk: Vec<u8>, der: Vec<u8>) -> Results<bool> {
        verify(msg.as_bytes(), pk.as_slice(), der.as_slice())
    }
}

impl SKVerify<String, Vec<u8>, String> for SM2 {
    fn verify(msg: String, pk: Vec<u8>, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<String, Vec<u8>, &str> for SM2 {
    fn verify(msg: String, pk: Vec<u8>, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<String, String, &[u8]> for SM2 {
    fn verify(msg: String, pk: String, der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), &Base64::decode(pk)?.as_slice(), der)
    }
}

impl SKVerify<String, String, Vec<u8>> for SM2 {
    fn verify(msg: String, pk: String, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<String, String, String> for SM2 {
    fn verify(msg: String, pk: String, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            &Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<String, String, &str> for SM2 {
    fn verify(msg: String, pk: String, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<String, &str, &[u8]> for SM2 {
    fn verify(msg: String, pk: &str, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der,
        )
    }
}

impl SKVerify<String, &str, Vec<u8>> for SM2 {
    fn verify(msg: String, pk: &str, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<String, &str, String> for SM2 {
    fn verify(msg: String, pk: &str, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<String, &str, &str> for SM2 {
    fn verify(msg: String, pk: &str, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            &Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&str, &[u8], &[u8]> for SM2 {
    fn verify(msg: &str, pk: &[u8], der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), pk, der)
    }
}

impl SKVerify<&str, &[u8], Vec<u8>> for SM2 {
    fn verify(msg: &str, pk: &[u8], der: Vec<u8>) -> Results<bool> {
        verify(msg.as_bytes(), pk, der.as_slice())
    }
}

impl SKVerify<&str, &[u8], String> for SM2 {
    fn verify(msg: &str, pk: &[u8], der: String) -> Results<bool> {
        verify(msg.as_bytes(), pk, Base64::decode(der)?.as_slice())
    }
}

impl SKVerify<&str, &[u8], &str> for SM2 {
    fn verify(msg: &str, pk: &[u8], der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk,
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&str, Vec<u8>, &[u8]> for SM2 {
    fn verify(msg: &str, pk: Vec<u8>, der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), pk.as_slice(), der)
    }
}

impl SKVerify<&str, Vec<u8>, Vec<u8>> for SM2 {
    fn verify(msg: &str, pk: Vec<u8>, der: Vec<u8>) -> Results<bool> {
        verify(msg.as_bytes(), pk.as_slice(), der.as_slice())
    }
}

impl SKVerify<&str, Vec<u8>, String> for SM2 {
    fn verify(msg: &str, pk: Vec<u8>, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<&str, Vec<u8>, &str> for SM2 {
    fn verify(msg: &str, pk: Vec<u8>, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            pk.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&str, String, &[u8]> for SM2 {
    fn verify(msg: &str, pk: String, der: &[u8]) -> Results<bool> {
        verify(msg.as_bytes(), &Base64::decode(pk)?.as_slice(), der)
    }
}

impl SKVerify<&str, String, Vec<u8>> for SM2 {
    fn verify(msg: &str, pk: String, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<&str, String, String> for SM2 {
    fn verify(msg: &str, pk: String, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            &Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<&str, String, &str> for SM2 {
    fn verify(msg: &str, pk: String, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerify<&str, &str, &[u8]> for SM2 {
    fn verify(msg: &str, pk: &str, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der,
        )
    }
}

impl SKVerify<&str, &str, Vec<u8>> for SM2 {
    fn verify(msg: &str, pk: &str, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerify<&str, &str, String> for SM2 {
    fn verify(msg: &str, pk: &str, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerify<&str, &str, &str> for SM2 {
    fn verify(msg: &str, pk: &str, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            &Base64::decode(pk.to_string())?.as_slice(),
            &Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerifyPath<&[u8], &[u8]> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &[u8], pk_filepath: P, der: &[u8]) -> Results<bool> {
        verify(msg, load_key_from_file(pk_filepath)?.as_slice(), der)
    }
}

impl SKVerifyPath<&[u8], Vec<u8>> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &[u8], pk_filepath: P, der: Vec<u8>) -> Results<bool> {
        verify(
            msg,
            load_key_from_file(pk_filepath)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerifyPath<&[u8], String> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &[u8], pk_filepath: P, der: String) -> Results<bool> {
        verify(
            msg,
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerifyPath<&[u8], &str> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &[u8], pk_filepath: P, der: &str) -> Results<bool> {
        verify(
            msg,
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerifyPath<Vec<u8>, &[u8]> for SM2 {
    fn verify<P: AsRef<Path>>(msg: Vec<u8>, pk_filepath: P, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der,
        )
    }
}

impl SKVerifyPath<Vec<u8>, Vec<u8>> for SM2 {
    fn verify<P: AsRef<Path>>(msg: Vec<u8>, pk_filepath: P, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerifyPath<Vec<u8>, String> for SM2 {
    fn verify<P: AsRef<Path>>(msg: Vec<u8>, pk_filepath: P, der: String) -> Results<bool> {
        verify(
            msg.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerifyPath<Vec<u8>, &str> for SM2 {
    fn verify<P: AsRef<Path>>(msg: Vec<u8>, pk_filepath: P, der: &str) -> Results<bool> {
        verify(
            msg.as_slice(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerifyPath<String, &[u8]> for SM2 {
    fn verify<P: AsRef<Path>>(msg: String, pk_filepath: P, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der,
        )
    }
}

impl SKVerifyPath<String, Vec<u8>> for SM2 {
    fn verify<P: AsRef<Path>>(msg: String, pk_filepath: P, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerifyPath<String, String> for SM2 {
    fn verify<P: AsRef<Path>>(msg: String, pk_filepath: P, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerifyPath<String, &str> for SM2 {
    fn verify<P: AsRef<Path>>(msg: String, pk_filepath: P, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

impl SKVerifyPath<&str, &[u8]> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &str, pk_filepath: P, der: &[u8]) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der,
        )
    }
}

impl SKVerifyPath<&str, Vec<u8>> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &str, pk_filepath: P, der: Vec<u8>) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            der.as_slice(),
        )
    }
}

impl SKVerifyPath<&str, String> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &str, pk_filepath: P, der: String) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der)?.as_slice(),
        )
    }
}

impl SKVerifyPath<&str, &str> for SM2 {
    fn verify<P: AsRef<Path>>(msg: &str, pk_filepath: P, der: &str) -> Results<bool> {
        verify(
            msg.as_bytes(),
            load_key_from_file(pk_filepath)?.as_slice(),
            Base64::decode(der.to_string())?.as_slice(),
        )
    }
}

////////// sm verify end //////////

fn stores<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, key) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn store_hex_key<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, Hex::encode(key)) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn store_hex_bytes_key<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, Hex::encode(key)) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn store_base64_key<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, Base64::encode(key)) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn store_base64_bytes_key<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, Base64::encode(key)) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn store_key<P: AsRef<Path>>(key: String, key_filepath: P) -> Results<()> {
    match Filer::write_force(key_filepath, key) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strs("store key", err)),
    }
}

fn load_key_string_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<String> {
    match read_to_string(key_filepath) {
        Ok(res) => Ok(res),
        Err(err) => Err(Errs::strs("read", err)),
    }
}

fn load_key_from_file<P: AsRef<Path>>(key_filepath: P) -> Results<Vec<u8>> {
    match read_to_string(key_filepath) {
        Ok(res) => Ok(Base64::decode(res)?),
        Err(err) => Err(Errs::strs("read", err)),
    }
}

fn new_keypair() -> Results<(SigCtx, Point, BigUint)> {
    let ctx = SigCtx::new();
    match ctx.new_keypair() {
        Ok((pk, sk)) => Ok((ctx, pk, sk)),
        Err(err) => Err(Errs::strs("sm2 new_keypair failed!", err)),
    }
}

fn generate() -> Results<(Vec<u8>, Vec<u8>)> {
    let (ctx, pk, sk) = new_keypair()?;
    match ctx.serialize_seckey(&sk) {
        Ok(seckey) => match ctx.serialize_pubkey(&pk, true) {
            Ok(pubkey) => Ok((seckey, pubkey)),
            Err(err) => Err(Errs::strs("sm2 generate serialize_pubkey failed!", err)),
        },
        Err(err) => Err(Errs::strs("sm2 generate serialize_seckey failed!", err)),
    }
}

fn generate_hex() -> Results<(String, String)> {
    let (sk, pk) = generate()?;
    Ok((Hex::encode(sk), Hex::encode(pk)))
}

fn generate_base64() -> Results<(String, String)> {
    let (sk, pk) = generate()?;
    Ok((Base64::encode(sk), Base64::encode(pk)))
}

fn generate_sk() -> Results<Vec<u8>> {
    let (ctx, _pk, sk) = new_keypair()?;
    match ctx.serialize_seckey(&sk) {
        Ok(src) => Ok(src),
        Err(err) => Err(Errs::strs("sm2 generate_sk serialize_seckey failed!", err)),
    }
}

fn generate_pk_from_sk(sk: Vec<u8>) -> Results<Vec<u8>> {
    let ctx = SigCtx::new();
    match ctx.load_seckey(sk.as_slice()) {
        Ok(sk) => match ctx.pk_from_sk(&sk) {
            Ok(pk) => match ctx.serialize_pubkey(&pk, true) {
                Ok(src) => Ok(src),
                Err(err) => Err(Errs::strs("sm2 generate_pk_from_sk serialize_pubkey", err)),
            }
            Err(err) => Err(Errs::strs("sm2 generate_pk_from_sk pk_from_sk", err)),
        },
        Err(err) => Err(Errs::strs("sm2 generate_pk_from_sk load_seckey", err)),
    }
}

fn generate_pk_from_sk_hex(sk: String) -> Results<Vec<u8>> {
    generate_pk_from_sk(Hex::decode(sk)?)
}

fn generate_pk_from_sk_base64(sk: String) -> Results<Vec<u8>> {
    generate_pk_from_sk(Base64::decode(sk)?)
}

fn generate_pk_from_sk_hex_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
    match read_to_string(sk_filepath) {
        Ok(sk) => generate_pk_from_sk_hex(sk),
        Err(err) => Err(Errs::strs("read to string", err)),
    }
}

fn generate_pk_from_sk_base64_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
    match read_to_string(sk_filepath) {
        Ok(sk) => generate_pk_from_sk_base64(sk),
        Err(err) => Err(Errs::strs("read to string", err)),
    }
}

fn generate_in_file<P: AsRef<Path>>(
    sk_filepath: P,
    pk_filepath: P,
) -> Results<(Vec<u8>, Vec<u8>)> {
    let (sk_bytes, pk_bytes) = generate()?;
    store_base64_bytes_key(sk_bytes.clone(), sk_filepath)?;
    store_base64_bytes_key(pk_bytes.clone(), pk_filepath)?;
    Ok((sk_bytes, pk_bytes))
}

fn generate_hex_in_file<P: AsRef<Path>>(
    sk_filepath: P,
    pk_filepath: P,
) -> Results<(String, String)> {
    let (sk_str, pk_str) = generate_hex()?;
    store_key(sk_str.clone(), sk_filepath)?;
    store_key(pk_str.clone(), pk_filepath)?;
    Ok((sk_str, pk_str))
}

fn generate_base64_in_file<P: AsRef<Path>>(
    sk_filepath: P,
    pk_filepath: P,
) -> Results<(String, String)> {
    let (sk_str, pk_str) = generate_base64()?;
    store_key(sk_str.clone(), sk_filepath)?;
    store_key(pk_str.clone(), pk_filepath)?;
    Ok((sk_str, pk_str))
}

fn generate_sk_in_file<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
    let (sk_bytes, _pk_bytes) = generate()?;
    store_base64_bytes_key(sk_bytes.clone(), sk_filepath)?;
    Ok(sk_bytes)
}

fn generate_sk_hex_in_file<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
    let (sk_str, _pk_str) = generate_hex()?;
    store_key(sk_str.clone(), sk_filepath)?;
    Ok(sk_str)
}

fn generate_sk_base64_in_file<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
    let (sk_str, _pk_str) = generate_base64()?;
    store_key(sk_str.clone(), sk_filepath)?;
    Ok(sk_str)
}

fn sign(msg: &[u8], sk: &[u8], pk: &[u8]) -> Results<Vec<u8>> {
    let ctx = SigCtx::new();
    let pk_point = match ctx.load_pubkey(pk) {
        Ok(pp) => pp,
        Err(err) => return Err(Errs::strs("sm2 sign load_pubkey failed!", err)),
    };
    let sig = match ctx.load_seckey(sk) {
        Ok(sk_bu) => match ctx.sign(msg, &sk_bu, &pk_point) {
            Ok(src) => src,
            Err(err) => return Err(Errs::strs("sm2 sign load_seckey sign failed!", err)),
        },
        Err(err) => return Err(Errs::strs("sm2 sign load_seckey failed!", err)),
    };
    Ok(sig.der_encode())
}

fn verify(msg: &[u8], pk: &[u8], der: &[u8]) -> Results<bool> {
    let ctx = SigCtx::new();
    let pk_point = match ctx.load_pubkey(pk) {
        Ok(pp) => pp,
        Err(err) => return Err(Errs::strs("sm2 verify load_pubkey failed!", err)),
    };
    let sig = match Signature::der_decode(der) {
        Ok(s) => s,
        Err(err) => return Err(Errs::strs("sm2 verify der_decode failed!", err)),
    };
    match ctx.verify(msg, &pk_point, &sig) {
        Ok(src) => Ok(src),
        Err(err) => Err(Errs::strs("sm2 verify verify failed!", err)),
    }
}


#[cfg(test)]
mod sm2_test {
    #[cfg(test)]
    mod sm {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::hex::Hex;
        use crate::cryptos::sm2::{SKLoadKey, SKStore};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn test() {
            let sm2 = SM2::new().unwrap();
            println!("sk0 base64 = {}", Base64::encode(sm2.sk_bytes().unwrap()));
            println!("pk0 base64 = {}", Base64::encode(sm2.pk_bytes().unwrap()));
            println!("sk0 hex = {}", Hex::encode(sm2.sk_bytes().unwrap()));
            println!("pk0 hex = {}", Hex::encode(sm2.pk_bytes().unwrap()));
            let pk1 = sm2.new_pk().unwrap();
            println!("pk1 base64 = {}", Base64::encode(pk1.clone()));
            println!("pk1 hex = {}", Hex::encode(pk1.clone()));

            let res1 = "hello world!".as_bytes();
            let sign_res = sm2.sig(res1).unwrap();
            println!(
                "verify = {}",
                sm2.verifies(res1, sign_res.as_slice()).unwrap()
            );
            let res2 = "hello world".as_bytes();
            println!(
                "verify = {}",
                sm2.verifies(res2, sign_res.as_slice()).unwrap()
            );

            sm2.store(
                "src/test/crypto/sm2/self/generate1_sk",
                "src/test/crypto/sm2/self/generate1_pk",
            )
                .unwrap();

            let sm2_new = SM2::load(
                "src/test/crypto/sm2/self/generate1_sk",
                "src/test/crypto/sm2/self/generate1_pk",
            )
                .unwrap();
            println!(
                "verify = {}",
                sm2_new.verifies(res1, sign_res.as_slice()).unwrap()
            );
        }
    }

    #[cfg(test)]
    mod generate {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::SM2;
        use crate::cryptos::sm2::SKNew;

        #[test]
        fn test() {
            let (sk, pk) = SM2::generate().unwrap();
            println!("sk = {}\npk = {}", Base64::encode(sk), Base64::encode(pk));
            let (sk, pk) = SM2::generate().unwrap();
            println!("sk = {}\npk = {}", Base64::encode(sk), Base64::encode(pk));
            let (sk, pk) = SM2::generate_base64().unwrap();
            println!("sk = {}\npk = {}", sk, pk);
            let (sk, pk) = SM2::generate_base64().unwrap();
            println!("sk = {}\npk = {}", sk, pk);
        }
    }

    #[cfg(test)]
    mod generate_sk {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::SM2;
        use crate::cryptos::sm2::SkNew;

        #[test]
        fn test() {
            let sk = SM2::generate().unwrap();
            println!("sk = {}", Base64::encode(sk));
            let sk = SM2::generate().unwrap();
            println!("sk = {}", Base64::encode(sk));
            let sk = SM2::generate_base64().unwrap();
            println!("sk = {}", sk);
            let sk = SM2::generate_base64().unwrap();
            println!("sk = {}", sk);
        }
    }

    #[cfg(test)]
    mod generate_sk_file {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::SM2;
        use crate::cryptos::sm2::SkNewStore;

        #[test]
        fn test() {
            let path1 = "src/test/crypto/sm2/generate_sk_file/generate1_sk";
            let path2 = "src/test/crypto/sm2/generate_sk_file/generate2_sk";
            let path3 = "src/test/crypto/sm2/generate_sk_file/generate3_sk";
            let path4 = "src/test/crypto/sm2/generate_sk_file/generate4_sk";
            let sk = SM2::generate(path1).unwrap();
            println!("sk = {}", Base64::encode(sk));
            let sk = SM2::generate(path2).unwrap();
            println!("sk = {}", Base64::encode(sk));
            let sk = SM2::generate_base64(path3).unwrap();
            println!("sk = {}", sk);
            let sk = SM2::generate_base64(path4).unwrap();
            println!("sk = {}", sk);
        }
    }

    #[cfg(test)]
    mod generate_file {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::SM2;
        use crate::cryptos::sm2::SKNewStore;

        #[test]
        fn test1() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/generate_file/generate1_sk",
                "src/test/crypto/sm2/generate_file/generate1_pk",
            )
                .unwrap();
            println!("sk = {}\npk = {}", Base64::encode(sk), Base64::encode(pk));
            let (sk, pk) = SM2::generate_base64(
                "src/test/crypto/sm2/generate_file/generate2_sk",
                "src/test/crypto/sm2/generate_file/generate2_pk",
            )
                .unwrap();
            println!("sk = {}\npk = {}", sk, pk);
        }

        #[test]
        fn test2() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/generate_file/generate3_sk".to_string(),
                "src/test/crypto/sm2/generate_file/generate3_pk".to_string(),
            )
                .unwrap();
            println!("sk = {}\npk = {}", Base64::encode(sk), Base64::encode(pk));
            let (sk, pk) = SM2::generate_base64(
                "src/test/crypto/sm2/generate_file/generate4_sk".to_string(),
                "src/test/crypto/sm2/generate_file/generate4_pk".to_string(),
            )
                .unwrap();
            println!("sk = {}\npk = {}", sk, pk);
        }
    }

    #[cfg(test)]
    mod generate_pk_v8s {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNew, SKPk};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn generate_pk_test() {
            let (sk, pk) = SM2::generate().unwrap();
            let pk_new = SM2::generate_pk(sk.clone()).unwrap();
            println!(
                "sk = {}\npk = {}\nne = {}",
                Base64::encode(sk),
                Base64::encode(pk),
                Base64::encode(pk_new)
            );

            let (sk, pk) = SM2::generate_base64().unwrap();
            let pk_new = SM2::generate_pk_by_base64(sk.clone()).unwrap();
            println!("sk = {}\npk = {}\nne = {}", sk, pk, Base64::encode(pk_new));
        }
    }

    #[cfg(test)]
    mod generate_pk_string {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNew, SKPk};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn generate_pk_test() {
            let (sk, pk) = SM2::generate().unwrap();
            let pk_new = SM2::generate_pk(sk.clone()).unwrap();
            println!(
                "sk = {}\npk = {}\nne = {}",
                Base64::encode(sk),
                Base64::encode(pk),
                Base64::encode(pk_new)
            );

            let (sk, pk) = SM2::generate_base64().unwrap();
            let pk_new = SM2::generate_pk_by_base64(sk.clone()).unwrap();
            println!("sk = {}\npk = {}\nne = {}", sk, pk, Base64::encode(pk_new));
        }
    }

    #[cfg(test)]
    mod generate_pk_v8s_path {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNewStore, SKPk};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn generate_pk_test() {
            let (_, pk) = SM2::generate(
                "src/test/crypto/sm2/generate_pk_file/generate1_sk",
                "src/test/crypto/sm2/generate_pk_file/generate1_pk",
            )
                .unwrap();
            let pk_new = SM2::generate_pk_by_base64_file(
                "src/test/crypto/sm2/generate_pk_file/generate1_sk".to_string(),
            )
                .unwrap();
            println!(
                "pk = {}\nne = {}",
                Base64::encode(pk),
                Base64::encode(pk_new)
            );
        }
    }

    #[cfg(test)]
    mod generate_pk_string_path {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNewStore, SKPk};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn generate_pk_test() {
            let (_, pk) = SM2::generate_base64(
                "src/test/crypto/sm2/generate_pk_file/generate2_sk",
                "src/test/crypto/sm2/generate_pk_file/generate2_pk",
            )
                .unwrap();
            let pk_new = SM2::generate_pk_by_base64_file(
                "src/test/crypto/sm2/generate_pk_file/generate2_sk".to_string(),
            )
                .unwrap();
            println!("pk = {}\nne = {}", pk, Base64::encode(pk_new));
        }
    }

    #[cfg(test)]
    mod sign {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNewStore, SKSign, SKVerify};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn test_u8s() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/sign/generate1_sk",
                "src/test/crypto/sm2/sign/generate1_pk",
            )
                .unwrap();
            let msg1 = "hello 你好！?";
            let pk_string = Base64::encode(pk.clone());
            let pk_str = pk_string.as_str();

            /////////////// sk/pk u8s start ///////////////
            let sign_res1 = SM2::sign(msg1, sk.as_slice(), pk.as_slice()).unwrap();
            let sign_res2 = SM2::sign_base64(msg1, sk.as_slice(), pk.as_slice()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.to_string(), sk.as_slice(), pk.as_slice()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.to_string(), sk.as_slice(), pk.as_slice()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.as_bytes(), sk.as_slice(), pk.as_slice()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes(), sk.as_slice(), pk.as_slice()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.as_bytes().to_vec(), sk.as_slice(), pk.as_slice()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes().to_vec(), sk.as_slice(), pk.as_slice()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );
            /////////////// sk/pk u8s end ///////////////
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk.as_slice(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_str.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.as_str(),
                )
                    .unwrap()
            );
        }

        #[test]
        fn test_v8s() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/sign/generate2_sk",
                "src/test/crypto/sm2/sign/generate2_pk",
            )
                .unwrap();
            let msg1 = "hello 你好！?";
            let pk_string = Base64::encode(pk.clone());
            let pk_str = pk_string.as_str();

            /////////////// sk/pk v8s start ///////////////
            let sign_res1 = SM2::sign(msg1, sk.clone(), pk.clone()).unwrap();
            let sign_res2 = SM2::sign_base64(msg1, sk.clone(), pk.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.to_string(), sk.clone(), pk.clone()).unwrap();
            let sign_res2 = SM2::sign_base64(msg1.to_string(), sk.clone(), pk.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.as_bytes(), sk.clone(), pk.clone()).unwrap();
            let sign_res2 = SM2::sign_base64(msg1.as_bytes(), sk.clone(), pk.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.as_bytes().to_vec(), sk.clone(), pk.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes().to_vec(), sk.clone(), pk.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );
            /////////////// sk/pk v8s end ///////////////
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk.as_slice(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_str.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.as_str(),
                )
                    .unwrap()
            );
        }

        #[test]
        fn test_string() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/sign/generate3_sk",
                "src/test/crypto/sm2/sign/generate3_pk",
            )
                .unwrap();
            let msg1 = "hello 你好！?";
            let sk_string = Base64::encode(sk.clone());
            let pk_string = Base64::encode(pk.clone());
            let pk_str = pk_string.as_str();

            /////////////// sk/pk string start ///////////////
            let sign_res1 = SM2::sign(msg1.clone(), sk_string.clone(), pk_string.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.clone(), sk_string.clone(), pk_string.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.to_string(), sk_string.clone(), pk_string.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.to_string(), sk_string.clone(), pk_string.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.as_bytes(), sk_string.clone(), pk_string.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes(), sk_string.clone(), pk_string.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(
                msg1.as_bytes().to_vec(),
                sk_string.clone(),
                pk_string.clone(),
            )
                .unwrap();
            let sign_res2 = SM2::sign_base64(
                msg1.as_bytes().to_vec(),
                sk_string.clone(),
                pk_string.clone(),
            )
                .unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );
            /////////////// sk/pk string end ///////////////
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk.as_slice(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_str.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.as_str(),
                )
                    .unwrap()
            );
        }

        #[test]
        fn test_str() {
            let (sk, pk) = SM2::generate(
                "src/test/crypto/sm2/sign/generate4_sk",
                "src/test/crypto/sm2/sign/generate4_pk",
            )
                .unwrap();
            let msg1 = "hello 你好！?";
            let sk_string = Base64::encode(sk.clone());
            let pk_string = Base64::encode(pk.clone());
            let sk_str = sk_string.as_str();
            let pk_str = pk_string.as_str();

            /////////////// sk/pk str start ///////////////
            let sign_res1 = SM2::sign(msg1, sk_str, pk_str).unwrap();
            let sign_res2 = SM2::sign_base64(msg1, sk_str.clone(), pk_str.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.to_string(), sk_str.clone(), pk_str.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.to_string(), sk_str.clone(), pk_str.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(msg1.as_bytes(), sk_str.clone(), pk_str.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes(), sk_str.clone(), pk_str.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.as_bytes().to_vec(), sk_str.clone(), pk_str.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes().to_vec(), sk_str.clone(), pk_str.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );
            /////////////// sk/pk str end ///////////////
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res1.as_slice()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.clone()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_string.clone(), sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk.as_slice(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_str.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res1.as_slice(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.clone(),
                )
                    .unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.as_slice(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_str.clone(), sign_res2.as_str()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(
                    msg1.as_bytes().to_vec(),
                    pk_string.clone(),
                    sign_res2.as_str(),
                )
                    .unwrap()
            );
        }
    }

    #[cfg(test)]
    mod sign_filepath {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::Encoder;
        use crate::cryptos::sm2::{SKNewStore, SKSignPath, SKVerifyPath};
        use crate::cryptos::sm2::SM2;

        #[test]
        fn test() {
            let sk_filepath = "src/test/crypto/sm2/sign/generate5_sk";
            let pk_filepath = "src/test/crypto/sm2/sign/generate5_pk";
            let (_, _) = SM2::generate(sk_filepath, pk_filepath).unwrap();
            let msg1 = "hello 你好！?";

            let sign_res1 = SM2::sign(msg1, sk_filepath.clone(), pk_filepath.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1, sk_filepath.clone(), pk_filepath.clone()).unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.to_string(), sk_filepath.clone(), pk_filepath.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.to_string(), sk_filepath.clone(), pk_filepath.clone())
                    .unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 =
                SM2::sign(msg1.as_bytes(), sk_filepath.clone(), pk_filepath.clone()).unwrap();
            let sign_res2 =
                SM2::sign_base64(msg1.as_bytes(), sk_filepath.clone(), pk_filepath.clone())
                    .unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1),
                sign_res2
            );

            let sign_res1 = SM2::sign(
                msg1.as_bytes().to_vec(),
                sk_filepath.clone(),
                pk_filepath.clone(),
            )
                .unwrap();
            let sign_res2 = SM2::sign_base64(
                msg1.as_bytes().to_vec(),
                sk_filepath.clone(),
                pk_filepath.clone(),
            )
                .unwrap();
            println!(
                "sign_res1 = {}\nsign_res2 = {}",
                Base64::encode(sign_res1.clone()),
                sign_res2
            );

            println!(
                "verify = {}",
                SM2::verify(msg1, pk_filepath, sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_filepath, sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_filepath, sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1, pk_filepath, sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_filepath, sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_filepath, sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_filepath, sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.to_string(), pk_filepath, sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_filepath, sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_filepath, sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_filepath, sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes(), pk_filepath, sign_res2.as_str()).unwrap()
            );

            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_filepath, sign_res1.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_filepath, sign_res1.as_slice()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_filepath, sign_res2.clone()).unwrap()
            );
            println!(
                "verify = {}",
                SM2::verify(msg1.as_bytes().to_vec(), pk_filepath, sign_res2.as_str()).unwrap()
            );
        }
    }

    #[cfg(test)]
    mod test_signature {
        use libsm::sm2::signature::{SigCtx, Signature};

        #[test]
        fn test_sig_encode_and_decode() {
            let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
            let msg = string.as_bytes();

            let ctx = SigCtx::new();
            let (pk, sk) = ctx.new_keypair().unwrap();

            let signature = ctx.sign(msg, &sk, &pk).unwrap();
            let der = signature.der_encode();
            let sig = Signature::der_decode(&der[..]).unwrap();
            assert!(ctx.verify(msg, &pk, &sig).unwrap());

            let signature = ctx.sign(msg, &sk, &pk).unwrap();
            let der = signature.der_encode();
            let sig = Signature::der_decode_raw(&der[2..]).unwrap();
            assert!(ctx.verify(msg, &pk, &sig).unwrap());
        }
    }
}
