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

use std::fs::read;
use std::fs::read_to_string;
use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::symm::Cipher;

use crate::cryptos::base64::{Base64Decoder, Base64Encoder};
use crate::cryptos::base64::Base64;
use crate::cryptos::hex::{HexDecoder, HexEncoder};
use crate::cryptos::Hex;
use crate::errors::Errs;
use crate::errors::Results;
use crate::io::file::Filer;
use crate::io::file::FilerWriter;
use crate::strings::StringHandler;
use crate::strings::Strings;

pub struct RSA {
    // /// 私钥位数
    // bits: u32,
    // /// 指定的密码算法
    // ///
    // /// Cipher Represents a particular cipher algorithm.
    // ///
    // /// See OpenSSL doc at [`EVP_EncryptInit`] for more information on each algorithms.
    // ///
    // /// [`EVP_EncryptInit`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html
    // cipher: Cipher,
    sk: PKey<Private>,
    pk: PKey<Public>,
    rsa_sk: Rsa<Private>,
    rsa_pk: Rsa<Public>,
}

pub trait RSANew {
    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a PEM-encoded PKCS#1 RSAPrivateKey structure.
    ///
    /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
    ///
    /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_pem(bits: u32) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a PEM-encoded PKCS#8 PrivateKeyInfo structure.
    ///
    /// The output will have a header of `-----BEGIN PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_PKCS8PrivateKey`].
    ///
    /// [`PEM_write_bio_PKCS8PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS8PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_pem(bits: u32) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
    ///
    /// This corresponds to [`i2d_RSAPrivateKey`].
    ///
    /// [`i2d_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_der(bits: u32) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded key type specific format.
    ///
    /// This corresponds to [`i2d_PrivateKey`].
    ///
    /// [`i2d_PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_der(bits: u32) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a PEM-encoded PKCS#1 RSAPrivateKey structure.
    ///
    /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
    ///
    /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_pem_string(bits: u32) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a PEM-encoded PKCS#8 PrivateKeyInfo structure.
    ///
    /// The output will have a header of `-----BEGIN PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_PKCS8PrivateKey`].
    ///
    /// [`PEM_write_bio_PKCS8PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS8PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_pem_string(bits: u32) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
    ///
    /// This corresponds to [`i2d_RSAPrivateKey`].
    ///
    /// [`i2d_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_der_base64(bits: u32) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded key type specific format.
    ///
    /// This corresponds to [`i2d_PrivateKey`].
    ///
    /// [`i2d_PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_der_base64(bits: u32) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
    ///
    /// This corresponds to [`i2d_RSAPrivateKey`].
    ///
    /// [`i2d_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_der_hex(bits: u32) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Serializes the private key to a DER-encoded key type specific format.
    ///
    /// This corresponds to [`i2d_PrivateKey`].
    ///
    /// [`i2d_PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_der_hex(bits: u32) -> Results<String>;
}

pub trait RSANewPass<T> {
    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Cipher Represents a particular cipher algorithm.
    ///
    /// See OpenSSL doc at [`EVP_EncryptInit`] for more information on each algorithms.
    ///
    /// [`EVP_EncryptInit`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html
    ///
    /// Serializes the private key to a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
    ///
    /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
    ///
    /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_pem_pass(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: T,
    ) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// bits 私钥位数
    ///
    /// Cipher Represents a particular cipher algorithm.
    ///
    /// See OpenSSL doc at [`EVP_EncryptInit`] for more information on each algorithms.
    ///
    /// [`EVP_EncryptInit`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html
    ///
    /// Serializes the private key to a PEM-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
    ///
    /// The output will have a header of `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_PKCS8PrivateKey`].
    ///
    /// [`PEM_write_bio_PKCS8PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS8PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_pem_pass(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: T,
    ) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Cipher Represents a particular cipher algorithm.
    ///
    /// See OpenSSL doc at [`EVP_EncryptInit`] for more information on each algorithms.
    ///
    /// [`EVP_EncryptInit`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html
    ///
    /// Serializes the private key to a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
    ///
    /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
    ///
    /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs1_pem_pass_string(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: T,
    ) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// bits 私钥位数
    ///
    /// Cipher Represents a particular cipher algorithm.
    ///
    /// See OpenSSL doc at [`EVP_EncryptInit`] for more information on each algorithms.
    ///
    /// [`EVP_EncryptInit`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html
    ///
    /// Serializes the private key to a PEM-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
    ///
    /// The output will have a header of `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
    ///
    /// This corresponds to [`PEM_write_bio_PKCS8PrivateKey`].
    ///
    /// [`PEM_write_bio_PKCS8PrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS8PrivateKey.html
    /// <p>
    ///
    /// # Return
    /// bytes，可以通过string(bytes)的方式查阅
    fn generate_pkcs8_pem_pass_string(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: T,
    ) -> Results<String>;
}

pub trait RSANewStore {
    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_pem<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_pem<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_pem_string<P: AsRef<Path>>(bits: u32, sk_filepath: P)
                                                 -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_pem_string<P: AsRef<Path>>(bits: u32, sk_filepath: P)
                                                 -> Results<String>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_der<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_der<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_der_base64<P: AsRef<Path>>(bits: u32, sk_filepath: P)
                                                 -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_der_base64<P: AsRef<Path>>(bits: u32, sk_filepath: P)
                                                 -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_der_hex<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_der_hex<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<String>;
}

pub trait RSANewPassStore<M> {
    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: M,
        sk_filepath: P,
    ) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字节数组
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: M,
        sk_filepath: P,
    ) -> Results<Vec<u8>>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs1_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: M,
        sk_filepath: P,
    ) -> Results<String>;

    /// 生成非对称加密私钥，返回sk字符串
    ///
    /// 并将生成的私钥存储在sk指定文件中
    fn generate_pkcs8_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: openssl::symm::Cipher,
        passphrase: M,
        sk_filepath: P,
    ) -> Results<String>;
}

pub trait RSAPkV8s<T> {
    /// 根据私钥生成公钥
    fn generate_pk(sk: T) -> Results<Vec<u8>>;
}

pub trait RSAPk2String<T> {
    /// 根据私钥生成公钥
    fn generate_pk(sk: T) -> Results<String>;
}

pub trait RSAPkKey<T> {
    /// 根据私钥生成公钥
    fn generate_pk(sk: T) -> Results<PKey<Public>>;
}

pub trait RSAPk<T> {
    /// 根据私钥生成公钥
    fn generate_pk_pkcs1(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8(sk: T) -> Results<Rsa<Public>>;
}

pub trait RSAPkString<T> {
    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_pem(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_pem(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_hex(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_hex(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_base64(sk: T) -> Results<Rsa<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_base64(sk: T) -> Results<Rsa<Public>>;
}

pub trait RSAPkString2String<T> {
    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_pem(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_pem(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_hex(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_hex(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs1_base64(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkcs8_base64(sk: T) -> Results<String>;
}

pub trait RSAPkKeyString2String<T> {
    /// 根据私钥生成公钥
    fn generate_pk_pkey_pem(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkey_hex(sk: T) -> Results<String>;

    /// 根据私钥生成公钥
    fn generate_pk_pkey_base64(sk: T) -> Results<String>;
}

pub trait RSAPkKeyString<T> {
    /// 根据私钥生成公钥
    fn generate_pk_pkey_pem(sk: T) -> Results<PKey<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkey_hex(sk: T) -> Results<PKey<Public>>;

    /// 根据私钥生成公钥
    fn generate_pk_pkey_base64(sk: T) -> Results<PKey<Public>>;
}

pub trait RSAPkKeyPath {
    /// 根据私钥文件生成公钥
    fn generate_pk<P: AsRef<Path>>(sk_filepath: P) -> Results<PKey<Public>>;
}

pub trait RSAPkPath {
    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1<P: AsRef<Path>>(sk_filepath: P) -> Results<Rsa<Public>>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8<P: AsRef<Path>>(sk_filepath: P) -> Results<Rsa<Public>>;
}

pub trait RSAPkV8sPath {
    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1_der<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8_der<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>>;
}

pub trait RSAPkStringPath {
    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1_der_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8_der_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs1_der_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;

    /// 根据私钥文件生成公钥
    fn generate_pk_pkcs8_der_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String>;
}

pub trait RSAStoreKey<M> {
    /// 将公/私钥存储在指定文件中
    fn store<P: AsRef<Path>>(key: M, key_filepath: P) -> Results<()>;
}

pub trait RSALoadKey {
    /// 从指定文件中读取公/私钥字节数组
    fn load_bytes<P: AsRef<Path>>(key_filepath: P) -> Results<Vec<u8>>;

    /// 从指定文件中读取公/私钥字符串
    fn load_string<P: AsRef<Path>>(key_filepath: P) -> Results<String>;

    /// 从指定文件中读取Pkey私钥
    fn load_sk<P: AsRef<Path>>(key_filepath: P) -> Results<PKey<Private>>;

    /// 从指定文件中读取Pkey公钥
    fn load_pk<P: AsRef<Path>>(key_filepath: P) -> Results<PKey<Public>>;

    /// 从指定文件中读取Rsa私钥
    fn load_rsa_sk<P: AsRef<Path>>(key_filepath: P) -> Results<Rsa<Private>>;

    /// 从指定文件中读取Rsa公钥
    fn load_rsa_pk<P: AsRef<Path>>(key_filepath: P) -> Results<Rsa<Public>>;
}

/// base method
impl RSA {
    /// 生成RSA对象
    pub fn new(bits: u32) -> Results<RSA> {
        let rsa_sk = generate(bits)?;
        let rsa_pk = generate_pk_rsa_pkcs1_from_rsa_sk(rsa_sk.clone())?;
        let sk = generate_pkey(rsa_sk.clone())?;
        let pk = generate_pkey(rsa_pk.clone())?;
        Ok(RSA {
            sk,
            pk,
            rsa_sk,
            rsa_pk,
        })
    }

    /// 生成RSA对象
    pub fn from(rsa_sk: Rsa<Private>) -> Results<RSA> {
        let rsa_pk = generate_pk_rsa_pkcs1_from_rsa_sk(rsa_sk.clone())?;
        let sk = generate_pkey(rsa_sk.clone())?;
        let pk = generate_pkey(rsa_pk.clone())?;
        Ok(RSA {
            sk,
            pk,
            rsa_sk,
            rsa_pk,
        })
    }

    /// 生成RSA对象
    pub fn from_pkey(sk: PKey<Private>) -> Results<RSA> {
        let pk = generate_pk_pkey_from_pkey_sk(sk.clone())?;
        let rsa_sk = generate_rsa(sk.clone())?;
        let rsa_pk = generate_pk_rsa_pkcs1_from_rsa_sk(rsa_sk.clone())?;
        Ok(RSA {
            sk,
            pk,
            rsa_sk,
            rsa_pk,
        })
    }

    /// 生成RSA对象
    pub fn from_bytes(sk: Vec<u8>) -> Results<RSA> {
        RSA::from_pkey(load_sk_pkey(sk)?)
    }

    /// 通过私钥文件生成RSA对象
    pub fn load<P: AsRef<Path>>(sk_filepath: P) -> Results<RSA> {
        let sk = load_sk_pkey_file(sk_filepath)?;
        RSA::from_pkey(sk)
    }

    /// 通过公私钥文件生成RSA对象
    pub fn load_all<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<RSA> {
        let sk = load_sk_pkey_file(sk_filepath)?;
        let pk = load_pk_pkey_file(pk_filepath)?;
        if !sk.public_eq(&pk) {
            Err(Errs::str("sk public_eq false"))
        } else {
            let rsa_sk = generate_rsa(sk.clone())?;
            let rsa_pk = generate_rsa(pk.clone())?;
            Ok(RSA {
                sk,
                pk,
                rsa_sk,
                rsa_pk,
            })
        }
    }

    // /// 通过公私钥文件生成RSA对象
    // pub fn store_pkcs1_pem<P: AsRef<Path>>(
    //     &self,
    //     sk_filepath: P,
    //     pk_filepath: P,
    // ) -> GeorgeResult<RSA> {
    //     let _ = Filer::write_force(sk_filepath, self.sk_pkcs1_pem()?)?;
    //     RSA::store(self.sk_pkcs1_pem()?, sk_filepath)?;
    //     RSA::store(self.pk_pkcs1_pem()?, pk_filepath)
    // }

    pub fn sk(&self) -> PKey<Private> {
        self.sk.clone()
    }

    pub fn pk(&self) -> PKey<Public> {
        self.pk.clone()
    }

    pub fn rsa_sk(&self) -> Rsa<Private> {
        self.rsa_sk.clone()
    }

    pub fn rsa_pk(&self) -> Rsa<Public> {
        self.rsa_pk.clone()
    }
}

/// pem method
impl RSA {
    pub fn sk_pkcs1_pem(&self) -> Results<Vec<u8>> {
        match self.rsa_sk.private_key_to_pem() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn pk_pkcs1_pem(&self) -> Results<Vec<u8>> {
        match self.rsa_pk.public_key_to_pem_pkcs1() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn sk_pkcs8_pem(&self) -> Results<Vec<u8>> {
        match self.sk.private_key_to_pem_pkcs8() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn pk_pkcs8_pem(&self) -> Results<Vec<u8>> {
        match self.pk.public_key_to_pem() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn sk_pkcs1_pem_str(&self) -> Results<String> {
        Strings::from_utf8(self.sk_pkcs1_pem()?)
    }

    pub fn pk_pkcs1_pem_str(&self) -> Results<String> {
        Strings::from_utf8(self.pk_pkcs1_pem()?)
    }

    pub fn sk_pkcs8_pem_str(&self) -> Results<String> {
        Strings::from_utf8(self.sk_pkcs8_pem()?)
    }

    pub fn pk_pkcs8_pem_str(&self) -> Results<String> {
        Strings::from_utf8(self.pk_pkcs8_pem()?)
    }

    pub fn sk_pkcs1_pem_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.sk_pkcs1_pem()?))
    }

    pub fn pk_pkcs1_pem_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.pk_pkcs1_pem()?))
    }

    pub fn sk_pkcs8_pem_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.sk_pkcs8_pem()?))
    }

    pub fn pk_pkcs8_pem_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.pk_pkcs8_pem()?))
    }

    pub fn sk_pkcs1_pem_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.sk_pkcs1_pem()?))
    }

    pub fn pk_pkcs1_pem_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.pk_pkcs1_pem()?))
    }

    pub fn sk_pkcs8_pem_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.sk_pkcs8_pem()?))
    }

    pub fn pk_pkcs8_pem_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.pk_pkcs8_pem()?))
    }
}

/// der method
impl RSA {
    pub fn sk_pkcs1_der(&self) -> Results<Vec<u8>> {
        match self.rsa_sk.private_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_der", err)),
        }
    }

    pub fn pk_pkcs1_der(&self) -> Results<Vec<u8>> {
        match self.rsa_pk.public_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("public_key_to_der", err)),
        }
    }

    pub fn sk_pkcs8_der(&self) -> Results<Vec<u8>> {
        match self.sk.private_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_der", err)),
        }
    }

    pub fn pk_pkcs8_der(&self) -> Results<Vec<u8>> {
        match self.pk.public_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("public_key_to_der", err)),
        }
    }

    pub fn sk_pkcs1_der_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.sk_pkcs1_der()?))
    }

    pub fn pk_pkcs1_der_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.pk_pkcs1_der()?))
    }

    pub fn sk_pkcs8_der_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.sk_pkcs8_der()?))
    }

    pub fn pk_pkcs8_der_hex(&self) -> Results<String> {
        Ok(Hex::encode(self.pk_pkcs8_der()?))
    }

    pub fn sk_pkcs1_der_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.sk_pkcs1_der()?))
    }

    pub fn pk_pkcs1_der_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.pk_pkcs1_der()?))
    }

    pub fn sk_pkcs8_der_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.sk_pkcs8_der()?))
    }

    pub fn pk_pkcs8_der_base64(&self) -> Results<String> {
        Ok(Base64::encode(self.pk_pkcs8_der()?))
    }
}

/// sign method
impl RSA {
    pub fn sign(&self, msg: &[u8]) -> Results<Vec<u8>> {
        let mut signer: Signer;
        match Signer::new(MessageDigest::sha256(), &self.sk) {
            Ok(sig) => signer = sig,
            Err(err) => return Err(Errs::strs("signer new", err)),
        }
        match signer.set_rsa_padding(Padding::PKCS1) {
            Err(err) => return Err(Errs::strs("signer set_rsa_padding", err)),
            _ => {}
        }
        match signer.update(msg) {
            Err(err) => return Err(Errs::strs("signer update", err)),
            _ => {}
        }
        match signer.sign_to_vec() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("signer sign_to_vec", err)),
        }
    }

    pub fn sign_cus(
        &self,
        msg: &[u8],
        digest: MessageDigest,
        padding: Padding,
    ) -> Results<Vec<u8>> {
        let mut signer: Signer;
        match Signer::new(digest, &self.sk) {
            Ok(sig) => signer = sig,
            Err(err) => return Err(Errs::strs("signer new", err)),
        }
        match signer.set_rsa_padding(padding) {
            Err(err) => return Err(Errs::strs("signer set_rsa_padding", err)),
            _ => {}
        }
        match signer.update(msg) {
            Err(err) => return Err(Errs::strs("signer update", err)),
            _ => {}
        }
        match signer.sign_to_vec() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("signer sign_to_vec", err)),
        }
    }

    pub fn verify(&self, msg: &[u8], der: &[u8]) -> Results<bool> {
        let mut verifier: Verifier;
        match Verifier::new(MessageDigest::sha256(), &self.pk) {
            Ok(ver) => verifier = ver,
            Err(err) => return Err(Errs::strs("verifier new", err)),
        }
        match verifier.update(msg) {
            Err(err) => return Err(Errs::strs("verifier update", err)),
            _ => {}
        }
        match verifier.verify(der) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("verifier verify", err)),
        }
    }

    pub fn verify_cus(
        &self,
        msg: &[u8],
        der: &[u8],
        digest: MessageDigest,
        padding: Padding,
    ) -> Results<bool> {
        let mut verifier: Verifier;
        match Verifier::new(digest, &self.pk) {
            Ok(ver) => verifier = ver,
            Err(err) => return Err(Errs::strs("verifier update", err)),
        }
        match verifier.set_rsa_padding(padding) {
            Err(err) => return Err(Errs::strs("verifier set_rsa_padding", err)),
            _ => {}
        }
        match verifier.update(msg) {
            Err(err) => return Err(Errs::strs("verifier update", err)),
            _ => {}
        }
        match verifier.verify(der) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("verifier verify", err)),
        }
    }
}

/// crypt method
impl RSA {
    pub fn encrypt_sk(&self, data: &[u8]) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_sk.size() as usize];
        match self
            .rsa_sk
            .private_encrypt(data, &mut emesg, Padding::PKCS1)
        {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("private_encrypt", err)),
        }
    }

    pub fn decrypt_sk(&self, data: &[u8]) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_sk.size() as usize];
        match self
            .rsa_sk
            .private_decrypt(data, &mut emesg, Padding::PKCS1)
        {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("private_decrypt", err)),
        }
    }

    pub fn encrypt_pk(&self, data: &[u8]) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_pk.size() as usize];
        match self.rsa_pk.public_encrypt(data, &mut emesg, Padding::PKCS1) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("public_encrypt", err)),
        }
    }

    pub fn decrypt_pk(&self, data: &[u8]) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_pk.size() as usize];
        match self.rsa_pk.public_decrypt(data, &mut emesg, Padding::PKCS1) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("public_decrypt", err)),
        }
    }

    pub fn encrypt_sk_padding(&self, data: &[u8], padding: Padding) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_sk.size() as usize];
        match self.rsa_sk.private_encrypt(data, &mut emesg, padding) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("private_encrypt", err)),
        }
    }

    pub fn decrypt_sk_padding(&self, data: &[u8], padding: Padding) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_sk.size() as usize];
        match self.rsa_sk.private_decrypt(data, &mut emesg, padding) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("private_decrypt", err)),
        }
    }

    pub fn encrypt_pk_padding(&self, data: &[u8], padding: Padding) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_pk.size() as usize];
        match self.rsa_pk.public_encrypt(data, &mut emesg, padding) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("public_encrypt", err)),
        }
    }

    pub fn decrypt_pk_padding(&self, data: &[u8], padding: Padding) -> Results<Vec<u8>> {
        let mut emesg = vec![0; self.rsa_pk.size() as usize];
        match self.rsa_pk.public_decrypt(data, &mut emesg, padding) {
            Ok(_) => Ok(emesg),
            Err(err) => Err(Errs::strs("public_decrypt", err)),
        }
    }
}

////////// generate pk start //////////

impl RSANew for RSA {
    fn generate_pkcs1_pem(bits: u32) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem(bits)
    }

    fn generate_pkcs8_pem(bits: u32) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem(bits)
    }

    fn generate_pkcs1_der(bits: u32) -> Results<Vec<u8>> {
        generate_pkcs1_sk_der(bits)
    }

    fn generate_pkcs8_der(bits: u32) -> Results<Vec<u8>> {
        generate_pkcs8_sk_der(bits)
    }

    fn generate_pkcs1_pem_string(bits: u32) -> Results<String> {
        generate_pkcs1_sk_pem_string(bits)
    }

    fn generate_pkcs8_pem_string(bits: u32) -> Results<String> {
        generate_pkcs8_sk_pem_string(bits)
    }

    fn generate_pkcs1_der_base64(bits: u32) -> Results<String> {
        generate_pkcs1_sk_der_base64_string(bits)
    }

    fn generate_pkcs8_der_base64(bits: u32) -> Results<String> {
        generate_pkcs8_sk_der_base64_string(bits)
    }

    fn generate_pkcs1_der_hex(bits: u32) -> Results<String> {
        generate_pkcs1_sk_der_hex_string(bits)
    }

    fn generate_pkcs8_der_hex(bits: u32) -> Results<String> {
        generate_pkcs8_sk_der_hex_string(bits)
    }
}

impl RSANewPass<&[u8]> for RSA {
    fn generate_pkcs1_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass(bits, cipher, passphrase)
    }

    fn generate_pkcs8_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass(bits, cipher, passphrase)
    }

    fn generate_pkcs1_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_string(bits, cipher, passphrase)
    }

    fn generate_pkcs8_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_string(bits, cipher, passphrase)
    }
}

impl RSANewPass<Vec<u8>> for RSA {
    fn generate_pkcs1_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass(bits, cipher, passphrase.as_slice())
    }

    fn generate_pkcs8_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass(bits, cipher, passphrase.as_slice())
    }

    fn generate_pkcs1_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_string(bits, cipher, passphrase.as_slice())
    }

    fn generate_pkcs8_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_string(bits, cipher, passphrase.as_slice())
    }
}

impl RSANewPass<&str> for RSA {
    fn generate_pkcs1_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs8_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs1_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_string(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs8_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_string(bits, cipher, passphrase.as_bytes())
    }
}

impl RSANewPass<String> for RSA {
    fn generate_pkcs1_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs8_pem_pass(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs1_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_string(bits, cipher, passphrase.as_bytes())
    }

    fn generate_pkcs8_pem_pass_string(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_string(bits, cipher, passphrase.as_bytes())
    }
}

impl RSANewStore for RSA {
    fn generate_pkcs1_pem<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_file(bits, sk_filepath)
    }

    fn generate_pkcs8_pem<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_file(bits, sk_filepath)
    }

    fn generate_pkcs1_pem_string<P: AsRef<Path>>(
        bits: u32,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_file_string(bits, sk_filepath)
    }

    fn generate_pkcs8_pem_string<P: AsRef<Path>>(
        bits: u32,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_file_string(bits, sk_filepath)
    }

    fn generate_pkcs1_der<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>> {
        generate_pkcs1_sk_der_file(bits, sk_filepath)
    }

    fn generate_pkcs8_der<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<Vec<u8>> {
        generate_pkcs8_sk_der_file(bits, sk_filepath)
    }

    fn generate_pkcs1_der_base64<P: AsRef<Path>>(
        bits: u32,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_der_base64_file(bits, sk_filepath)
    }

    fn generate_pkcs8_der_base64<P: AsRef<Path>>(
        bits: u32,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_der_base64_file(bits, sk_filepath)
    }

    fn generate_pkcs1_der_hex<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<String> {
        generate_pkcs1_sk_der_hex_file(bits, sk_filepath)
    }

    fn generate_pkcs8_der_hex<P: AsRef<Path>>(bits: u32, sk_filepath: P) -> Results<String> {
        generate_pkcs8_sk_der_hex_file(bits, sk_filepath)
    }
}

impl RSANewPassStore<String> for RSA {
    fn generate_pkcs1_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass_file(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass_file(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs1_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_file_string(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: String,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_file_string(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }
}

impl RSANewPassStore<&str> for RSA {
    fn generate_pkcs1_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass_file(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass_file(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs1_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_file_string(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &str,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_file_string(bits, cipher, passphrase.as_bytes(), sk_filepath)
    }
}

impl RSANewPassStore<Vec<u8>> for RSA {
    fn generate_pkcs1_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass_file(bits, cipher, passphrase.as_slice(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass_file(bits, cipher, passphrase.as_slice(), sk_filepath)
    }

    fn generate_pkcs1_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_file_string(bits, cipher, passphrase.as_slice(), sk_filepath)
    }

    fn generate_pkcs8_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: Vec<u8>,
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_file_string(bits, cipher, passphrase.as_slice(), sk_filepath)
    }
}

impl RSANewPassStore<&[u8]> for RSA {
    fn generate_pkcs1_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs1_sk_pem_pass_file(bits, cipher, passphrase, sk_filepath)
    }

    fn generate_pkcs8_pem_pass<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
        sk_filepath: P,
    ) -> Results<Vec<u8>> {
        generate_pkcs8_sk_pem_pass_file(bits, cipher, passphrase, sk_filepath)
    }

    fn generate_pkcs1_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs1_sk_pem_pass_file_string(bits, cipher, passphrase, sk_filepath)
    }

    fn generate_pkcs8_pem_pass_string<P: AsRef<Path>>(
        bits: u32,
        cipher: Cipher,
        passphrase: &[u8],
        sk_filepath: P,
    ) -> Results<String> {
        generate_pkcs8_sk_pem_pass_file_string(bits, cipher, passphrase, sk_filepath)
    }
}

////////// generate sk end //////////

////////// generate pk start //////////

impl RSAPkKey<&[u8]> for RSA {
    fn generate_pk(sk: &[u8]) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(sk.to_vec())
    }
}

impl RSAPkKey<Vec<u8>> for RSA {
    fn generate_pk(sk: Vec<u8>) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(sk)
    }
}

impl RSAPkKey<PKey<Private>> for RSA {
    fn generate_pk(sk: PKey<Private>) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk(sk)
    }
}

impl RSAPkKeyString<String> for RSA {
    fn generate_pk_pkey_pem(sk: String) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(sk.into_bytes())
    }

    fn generate_pk_pkey_hex(sk: String) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkey_base64(sk: String) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(Base64::decode(sk)?)
    }
}

impl RSAPkKeyString<&str> for RSA {
    fn generate_pk_pkey_pem(sk: &str) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(sk.as_bytes().to_vec())
    }

    fn generate_pk_pkey_hex(sk: &str) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkey_base64(sk: &str) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_bytes(Base64::decode(sk)?)
    }
}

impl RSAPk<Rsa<Private>> for RSA {
    fn generate_pk_pkcs1(sk: Rsa<Private>) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk(sk)
    }

    fn generate_pk_pkcs8(sk: Rsa<Private>) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk(sk)
    }
}

impl RSAPk<Vec<u8>> for RSA {
    fn generate_pk_pkcs1(sk: Vec<u8>) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(sk)
    }

    fn generate_pk_pkcs8(sk: Vec<u8>) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(sk)
    }
}

impl RSAPkString<String> for RSA {
    fn generate_pk_pkcs1_pem(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(sk.into_bytes())
    }

    fn generate_pk_pkcs8_pem(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(sk.into_bytes())
    }

    fn generate_pk_pkcs1_hex(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkcs8_hex(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkcs1_base64(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(Base64::decode(sk)?)
    }

    fn generate_pk_pkcs8_base64(sk: String) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(Base64::decode(sk)?)
    }
}

impl RSAPkString<&str> for RSA {
    fn generate_pk_pkcs1_pem(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(sk.as_bytes().to_vec())
    }

    fn generate_pk_pkcs8_pem(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(sk.as_bytes().to_vec())
    }

    fn generate_pk_pkcs1_hex(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkcs8_hex(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(Hex::decode(sk)?)
    }

    fn generate_pk_pkcs1_base64(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_bytes(Base64::decode(sk)?)
    }

    fn generate_pk_pkcs8_base64(sk: &str) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_bytes(Base64::decode(sk)?)
    }
}

impl RSAPkKeyPath for RSA {
    fn generate_pk<P: AsRef<Path>>(sk_filepath: P) -> Results<PKey<Public>> {
        generate_pk_pkey_from_pkey_sk_file(sk_filepath)
    }
}

impl RSAPkPath for RSA {
    fn generate_pk_pkcs1<P: AsRef<Path>>(sk_filepath: P) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs1_from_rsa_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8<P: AsRef<Path>>(sk_filepath: P) -> Results<Rsa<Public>> {
        generate_pk_rsa_pkcs8_from_rsa_sk_file(sk_filepath)
    }
}

impl RSAPkV8sPath for RSA {
    fn generate_pk_pkcs1_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_rsa_pkcs1_pem_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_rsa_pkcs8_pem_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs1_der<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_rsa_pkcs1_der_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8_der<P: AsRef<Path>>(sk_filepath: P) -> Results<Vec<u8>> {
        generate_pk_rsa_pkcs8_der_from_sk_file(sk_filepath)
    }
}

impl RSAPkStringPath for RSA {
    fn generate_pk_pkcs1_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs1_pem_string_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8_pem<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs8_pem_string_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs1_der_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs1_der_hex_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8_der_hex<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs8_der_base64_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs1_der_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs1_der_base64_from_sk_file(sk_filepath)
    }

    fn generate_pk_pkcs8_der_base64<P: AsRef<Path>>(sk_filepath: P) -> Results<String> {
        generate_pk_rsa_pkcs8_der_base64_from_sk_file(sk_filepath)
    }
}

////////// generate pk end //////////

////////// store end //////////

impl RSAStoreKey<String> for RSA {
    fn store<P: AsRef<Path>>(key: String, key_filepath: P) -> Results<()> {
        let _ = Filer::write_force(key_filepath, key)?;
        Ok(())
    }
}

impl RSAStoreKey<&str> for RSA {
    fn store<P: AsRef<Path>>(key: &str, key_filepath: P) -> Results<()> {
        let _ = Filer::write_force(key_filepath, key)?;
        Ok(())
    }
}

impl RSAStoreKey<Vec<u8>> for RSA {
    fn store<P: AsRef<Path>>(key: Vec<u8>, key_filepath: P) -> Results<()> {
        let _ = Filer::write_force(key_filepath, key)?;
        Ok(())
    }
}

impl RSAStoreKey<&[u8]> for RSA {
    fn store<P: AsRef<Path>>(key: &[u8], key_filepath: P) -> Results<()> {
        let _ = Filer::write_force(key_filepath, key)?;
        Ok(())
    }
}

////////// store end //////////

////////// load start //////////

impl RSALoadKey for RSA {
    fn load_bytes<P: AsRef<Path>>(key_filepath: P) -> Results<Vec<u8>> {
        load_bytes_from_file(key_filepath)
    }

    fn load_string<P: AsRef<Path>>(key_filepath: P) -> Results<String> {
        load_string_from_file(key_filepath)
    }

    fn load_sk<P: AsRef<Path>>(key_filepath: P) -> Results<PKey<Private>> {
        load_sk_pkey_file(key_filepath)
    }

    fn load_pk<P: AsRef<Path>>(key_filepath: P) -> Results<PKey<Public>> {
        load_pk_pkey_file(key_filepath)
    }

    fn load_rsa_sk<P: AsRef<Path>>(key_filepath: P) -> Results<Rsa<Private>> {
        load_sk_file(key_filepath)
    }

    fn load_rsa_pk<P: AsRef<Path>>(key_filepath: P) -> Results<Rsa<Public>> {
        load_pk_file(key_filepath)
    }
}

////////// load end //////////

fn generate(bits: u32) -> Results<Rsa<Private>> {
    match Rsa::generate(bits) {
        Ok(rsa) => Ok(rsa),
        Err(err) => Err(Errs::strs("generate_pkcs1", err)),
    }
}

fn generate_rsa<T>(key: PKey<T>) -> Results<Rsa<T>> {
    match key.rsa() {
        Ok(rsa) => Ok(rsa),
        Err(err) => Err(Errs::strs("generate_pkey", err)),
    }
}

fn generate_pkey<T>(rsa: Rsa<T>) -> Results<PKey<T>> {
    match PKey::from_rsa(rsa) {
        Ok(rsa) => Ok(rsa),
        Err(err) => Err(Errs::strs("generate_pkey", err)),
    }
}

fn generate_pkcs1_sk_pem(bits: u32) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match rsa.private_key_to_pem() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem_pkcs1", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

fn generate_pkcs8_sk_pem(bits: u32) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match PKey::from_rsa(rsa) {
            Ok(key) => match key.private_key_to_pem_pkcs8() {
                Ok(res) => Ok(res),
                Err(err) => Err(Errs::strs("private_key_to_pem_pkcs8", err)),
            },
            Err(err) => Err(Errs::strs("from_rsa", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

fn generate_pkcs1_sk_pem_pass(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match rsa.private_key_to_pem_passphrase(cipher, passphrase) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem_pkcs1", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

fn generate_pkcs8_sk_pem_pass(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match PKey::from_rsa(rsa) {
            Ok(key) => match key.private_key_to_pem_pkcs8_passphrase(cipher, passphrase) {
                Ok(res) => Ok(res),
                Err(err) => Err(Errs::strs("private_key_to_pem_pkcs8", err)),
            },
            Err(err) => Err(Errs::strs("from_rsa", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

fn generate_pkcs1_sk_der(bits: u32) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match rsa.private_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem_pkcs1", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

fn generate_pkcs8_sk_der(bits: u32) -> Results<Vec<u8>> {
    match Rsa::generate(bits) {
        Ok(rsa) => match PKey::from_rsa(rsa) {
            Ok(key) => match key.private_key_to_der() {
                Ok(res) => Ok(res),
                Err(err) => Err(Errs::strs("private_key_to_pem_pkcs8", err)),
            },
            Err(err) => Err(Errs::strs("from_rsa", err)),
        },
        Err(err) => Err(Errs::strs("generate", err)),
    }
}

/// 生成RSA私钥
///
/// bits 私钥位数
fn generate_pkcs1_sk_pem_string(bits: u32) -> Results<String> {
    match generate_pkcs1_sk_pem(bits) {
        Ok(v8s) => Strings::from_utf8(v8s),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs8_sk_pem_string(bits: u32) -> Results<String> {
    match generate_pkcs8_sk_pem(bits) {
        Ok(v8s) => Strings::from_utf8(v8s),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs1_sk_pem_pass_string(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
) -> Results<String> {
    match generate_pkcs1_sk_pem_pass(bits, cipher, passphrase) {
        Ok(v8s) => Strings::from_utf8(v8s),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs8_sk_pem_pass_string(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
) -> Results<String> {
    match generate_pkcs8_sk_pem_pass(bits, cipher, passphrase) {
        Ok(v8s) => Strings::from_utf8(v8s),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs1_sk_der_base64_string(bits: u32) -> Results<String> {
    match generate_pkcs1_sk_der(bits) {
        Ok(v8s) => Ok(Base64::encode(v8s)),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs8_sk_der_base64_string(bits: u32) -> Results<String> {
    match generate_pkcs8_sk_der(bits) {
        Ok(v8s) => Ok(Base64::encode(v8s)),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs1_sk_der_hex_string(bits: u32) -> Results<String> {
    match generate_pkcs1_sk_der(bits) {
        Ok(v8s) => Ok(hex::encode(v8s)),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

fn generate_pkcs8_sk_der_hex_string(bits: u32) -> Results<String> {
    match generate_pkcs8_sk_der(bits) {
        Ok(v8s) => Ok(hex::encode(v8s)),
        Err(err) => Err(Errs::strs("generate_sk_pem", err)),
    }
}

/// 生成RSA私钥并将私钥存储指定文件
///
/// bits 私钥位数
///
/// 如果已存在，删除重写
fn generate_pkcs1_sk_pem_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<Vec<u8>> {
    match generate_pkcs1_sk_pem(bits) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

/// 生成RSA私钥并将私钥存储指定文件
///
/// bits 私钥位数
///
/// 如果已存在，删除重写
fn generate_pkcs8_sk_pem_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<Vec<u8>> {
    match generate_pkcs8_sk_pem(bits) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_pem_file_string<P: AsRef<Path>>(
    bits: u32,
    filepath: P,
) -> Results<String> {
    match generate_pkcs1_sk_pem_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_pem_file_string<P: AsRef<Path>>(
    bits: u32,
    filepath: P,
) -> Results<String> {
    match generate_pkcs8_sk_pem_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_pem_pass_file<P: AsRef<Path>>(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
    filepath: P,
) -> Results<Vec<u8>> {
    match generate_pkcs1_sk_pem_pass(bits, cipher, passphrase) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_pem_pass_file<P: AsRef<Path>>(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
    filepath: P,
) -> Results<Vec<u8>> {
    match generate_pkcs8_sk_pem_pass(bits, cipher, passphrase) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_pem_pass_file_string<P: AsRef<Path>>(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
    filepath: P,
) -> Results<String> {
    match generate_pkcs1_sk_pem_pass_string(bits, cipher, passphrase) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_pem_pass_file_string<P: AsRef<Path>>(
    bits: u32,
    cipher: Cipher,
    passphrase: &[u8],
    filepath: P,
) -> Results<String> {
    match generate_pkcs8_sk_pem_pass_string(bits, cipher, passphrase) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_der_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<Vec<u8>> {
    match generate_pkcs1_sk_der(bits) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_der_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<Vec<u8>> {
    match generate_pkcs8_sk_der(bits) {
        Ok(v8s) => {
            Filer::write_force(filepath, v8s.clone())?;
            Ok(v8s)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_der_base64_file<P: AsRef<Path>>(
    bits: u32,
    filepath: P,
) -> Results<String> {
    match generate_pkcs1_sk_der_base64_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_der_base64_file<P: AsRef<Path>>(
    bits: u32,
    filepath: P,
) -> Results<String> {
    match generate_pkcs8_sk_der_base64_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs1_sk_der_hex_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<String> {
    match generate_pkcs1_sk_der_hex_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

fn generate_pkcs8_sk_der_hex_file<P: AsRef<Path>>(bits: u32, filepath: P) -> Results<String> {
    match generate_pkcs8_sk_der_hex_string(bits) {
        Ok(res) => {
            Filer::write_force(filepath, res.clone())?;
            Ok(res)
        }
        Err(err) => Err(Errs::strs("generate_sk", err)),
    }
}

/// 读取RSA私钥
fn load_sk_pkey_u8s(sk: &[u8]) -> Results<PKey<Private>> {
    match PKey::private_key_from_pem(sk) {
        Ok(key) => Ok(key),
        Err(_) => match PKey::private_key_from_pkcs8(sk) {
            Ok(key) => Ok(key),
            Err(_) => match PKey::private_key_from_der(sk) {
                Ok(key) => Ok(key),
                Err(err) => Err(Errs::strs("private_key_from_pem", err)),
            },
        },
    }
}

/// 读取RSA私钥
fn load_sk_pkey(sk: Vec<u8>) -> Results<PKey<Private>> {
    load_sk_pkey_u8s(sk.as_slice())
}

/// 读取RSA私钥
pub fn load_sk_pkey_file<P: AsRef<Path>>(filepath: P) -> Results<PKey<Private>> {
    match read(filepath.as_ref()) {
        Ok(v8s) => load_sk_pkey(v8s),
        Err(_) => match read_to_string(filepath.as_ref()) {
            Ok(res) => load_sk_pkey(Base64::decode(res)?),
            Err(_) => match read_to_string(filepath.as_ref()) {
                Ok(res) => load_sk_pkey(Hex::decode(res)?),
                Err(_) => match read_to_string(filepath) {
                    Ok(res) => load_sk_pkey_u8s(res.as_bytes()),
                    Err(err) => Err(Errs::strs("load_sk_pkey_file", err)),
                },
            },
        },
    }
}

/// 读取RSA公钥
fn load_pk_pkey_u8s(pk: &[u8]) -> Results<PKey<Public>> {
    match PKey::public_key_from_pem(pk) {
        Ok(key) => Ok(key),
        Err(_) => match PKey::public_key_from_der(pk) {
            Ok(key) => Ok(key),
            Err(err) => Err(Errs::strs("private_key_from_pem", err)),
        },
    }
}

/// 读取RSA公钥
fn load_pk_pkey(pk: Vec<u8>) -> Results<PKey<Public>> {
    load_pk_pkey_u8s(pk.as_slice())
}

/// 读取RSA公钥
pub fn load_pk_pkey_file<P: AsRef<Path>>(filepath: P) -> Results<PKey<Public>> {
    match read(filepath.as_ref()) {
        Ok(v8s) => load_pk_pkey(v8s),
        Err(_) => match read_to_string(filepath.as_ref()) {
            Ok(res) => load_pk_pkey(Base64::decode(res)?),
            Err(_) => match read_to_string(filepath.as_ref()) {
                Ok(res) => load_pk_pkey(Hex::decode(res)?),
                Err(_) => match read_to_string(filepath) {
                    Ok(res) => load_pk_pkey_u8s(res.as_bytes()),
                    Err(err) => Err(Errs::strs("load_sk_pkey_file", err)),
                },
            },
        },
    }
}

/// 读取RSA私钥
fn load_sk_u8s(sk: &[u8]) -> Results<Rsa<Private>> {
    match Rsa::private_key_from_pem(sk) {
        Ok(key) => Ok(key),
        Err(_) => match Rsa::private_key_from_der(sk) {
            Ok(key) => Ok(key),
            Err(err) => Err(Errs::strs("private_key_from_pem", err)),
        },
    }
}

/// 读取RSA私钥
fn load_sk(sk: Vec<u8>) -> Results<Rsa<Private>> {
    load_sk_u8s(sk.as_slice())
}

/// 读取RSA私钥
fn load_sk_file<P: AsRef<Path>>(filepath: P) -> Results<Rsa<Private>> {
    match read(filepath.as_ref()) {
        Ok(v8s) => load_sk(v8s),
        Err(_) => match read_to_string(filepath.as_ref()) {
            Ok(res) => load_sk(Base64::decode(res)?),
            Err(_) => match read_to_string(filepath.as_ref()) {
                Ok(res) => load_sk(Hex::decode(res)?),
                Err(_) => match read_to_string(filepath) {
                    Ok(res) => load_sk_u8s(res.as_bytes()),
                    Err(err) => Err(Errs::strs("load_sk_pkey_file", err)),
                },
            },
        },
    }
}

/// 读取RSA公钥
fn load_pk_u8s(pk: &[u8]) -> Results<Rsa<Public>> {
    match Rsa::public_key_from_pem(pk) {
        Ok(key) => Ok(key),
        Err(_) => match Rsa::public_key_from_pem_pkcs1(pk) {
            Ok(key) => Ok(key),
            Err(_) => match Rsa::public_key_from_der(pk) {
                Ok(key) => Ok(key),
                Err(_) => match Rsa::public_key_from_der_pkcs1(pk) {
                    Ok(key) => Ok(key),
                    Err(err) => Err(Errs::strs("private_key_from_pem", err)),
                },
            },
        },
    }
}

/// 读取RSA公钥
fn load_pk(pk: Vec<u8>) -> Results<Rsa<Public>> {
    load_pk_u8s(pk.as_slice())
}

/// 读取RSA公钥
pub fn load_pk_file<P: AsRef<Path>>(filepath: P) -> Results<Rsa<Public>> {
    match read(filepath.as_ref()) {
        Ok(v8s) => load_pk(v8s),
        Err(_) => match read_to_string(filepath.as_ref()) {
            Ok(res) => load_pk(Base64::decode(res)?),
            Err(_) => match read_to_string(filepath.as_ref()) {
                Ok(res) => load_pk(Hex::decode(res)?),
                Err(_) => match read_to_string(filepath) {
                    Ok(res) => load_pk_u8s(res.as_bytes()),
                    Err(err) => Err(Errs::strs("load_sk_pkey_file", err)),
                },
            },
        },
    }
}

/// 生成RSA公钥
fn generate_pk_pkey_from_pkey_sk(sk: PKey<Private>) -> Results<PKey<Public>> {
    match sk.public_key_to_pem() {
        Ok(u8s) => match PKey::public_key_from_pem(u8s.as_slice()) {
            Ok(pk) => Ok(pk),
            Err(err) => Err(Errs::strs("public_key_from_pem", err)),
        },
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_pkey_from_pkey_sk_bytes(sk: Vec<u8>) -> Results<PKey<Public>> {
    match load_sk_pkey(sk) {
        Ok(sk) => match sk.public_key_to_pem() {
            Ok(u8s) => match PKey::public_key_from_pem(u8s.as_slice()) {
                Ok(pk) => Ok(pk),
                Err(err) => Err(Errs::strs("public_key_from_pem", err)),
            },
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        },
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_pkey_from_pkey_sk_file<P: AsRef<Path>>(filepath: P) -> Results<PKey<Public>> {
    match load_sk_pkey_file(filepath) {
        Ok(sk) => match sk.public_key_to_pem() {
            Ok(u8s) => match PKey::public_key_from_pem(u8s.as_slice()) {
                Ok(pk) => Ok(pk),
                Err(err) => Err(Errs::strs("public_key_from_pem", err)),
            },
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        },
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_from_rsa_sk(sk: Rsa<Private>) -> Results<Rsa<Public>> {
    match sk.public_key_to_pem_pkcs1() {
        Ok(u8s) => match Rsa::public_key_from_pem_pkcs1(u8s.as_slice()) {
            Ok(pk) => Ok(pk),
            Err(err) => Err(Errs::strs("public_key_from_pem_pkcs1", err)),
        },
        Err(err) => Err(Errs::strs("public_key_to_pem_pkcs1", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_from_rsa_sk(sk: Rsa<Private>) -> Results<Rsa<Public>> {
    match sk.public_key_to_pem() {
        Ok(u8s) => match Rsa::public_key_from_pem(u8s.as_slice()) {
            Ok(pk) => Ok(pk),
            Err(err) => Err(Errs::strs("public_key_from_pem", err)),
        },
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_pem_from_rsa_sk(sk: Rsa<Private>) -> Results<Vec<u8>> {
    match sk.public_key_to_pem_pkcs1() {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_pem_from_rsa_sk(sk: Rsa<Private>) -> Results<Vec<u8>> {
    match sk.public_key_to_pem() {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_der_from_rsa_sk(sk: Rsa<Private>) -> Results<Vec<u8>> {
    match sk.public_key_to_der_pkcs1() {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_der_from_rsa_sk(sk: Rsa<Private>) -> Results<Vec<u8>> {
    match sk.public_key_to_der() {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strs("public_key_to_pem", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_from_rsa_sk_bytes(sk: Vec<u8>) -> Results<Rsa<Public>> {
    match load_sk(sk) {
        Ok(sk) => generate_pk_rsa_pkcs1_from_rsa_sk(sk),
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_from_rsa_sk_bytes(sk: Vec<u8>) -> Results<Rsa<Public>> {
    match load_sk(sk) {
        Ok(sk) => generate_pk_rsa_pkcs8_from_rsa_sk(sk),
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_from_rsa_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<Rsa<Public>> {
    match load_sk_file(filepath) {
        Ok(sk) => generate_pk_rsa_pkcs1_from_rsa_sk(sk),
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_from_rsa_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<Rsa<Public>> {
    match load_sk_file(filepath) {
        Ok(sk) => generate_pk_rsa_pkcs8_from_rsa_sk(sk),
        Err(err) => Err(Errs::strs("load_sk_pkey", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_pem_from_sk_file<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match load_sk_file(filepath) {
        Ok(key) => generate_pk_rsa_pkcs1_pem_from_rsa_sk(key),
        Err(err) => Err(Errs::strs("load_sk_file", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_pem_from_sk_file<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match load_sk_file(filepath) {
        Ok(key) => generate_pk_rsa_pkcs8_pem_from_rsa_sk(key),
        Err(err) => Err(Errs::strs("load_sk_file", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_pem_string_from_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<String> {
    Strings::from_utf8(generate_pk_rsa_pkcs1_pem_from_sk_file(filepath)?)
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_pem_string_from_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<String> {
    Strings::from_utf8(generate_pk_rsa_pkcs8_pem_from_sk_file(filepath)?)
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_der_hex_from_sk_file<P: AsRef<Path>>(filepath: P) -> Results<String> {
    Ok(Hex::encode(generate_pk_rsa_pkcs1_der_from_sk_file(
        filepath,
    )?))
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_der_base64_from_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<String> {
    Ok(Base64::encode(generate_pk_rsa_pkcs1_der_from_sk_file(
        filepath,
    )?))
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_der_base64_from_sk_file<P: AsRef<Path>>(
    filepath: P,
) -> Results<String> {
    Ok(Base64::encode(generate_pk_rsa_pkcs8_der_from_sk_file(
        filepath,
    )?))
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs1_der_from_sk_file<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match load_sk_file(filepath) {
        Ok(key) => generate_pk_rsa_pkcs1_der_from_rsa_sk(key),
        Err(err) => Err(Errs::strs("load_sk_file", err)),
    }
}

/// 生成RSA公钥
fn generate_pk_rsa_pkcs8_der_from_sk_file<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match load_sk_file(filepath) {
        Ok(key) => generate_pk_rsa_pkcs8_der_from_rsa_sk(key),
        Err(err) => Err(Errs::strs("load_sk_file", err)),
    }
}

/// 读取RSA公钥
fn load_bytes_from_file<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match read(filepath) {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strs("read", err)),
    }
}

/// 读取RSA公钥
fn load_string_from_file<P: AsRef<Path>>(filepath: P) -> Results<String> {
    match read_to_string(filepath) {
        Ok(res) => Ok(res),
        Err(err) => Err(Errs::strs("read", err)),
    }
}

#[cfg(test)]
mod rsa_test {
    #[cfg(test)]
    mod self_test {
        use openssl::hash::MessageDigest;
        use openssl::rsa::Padding;
        use openssl::sign::{Signer, Verifier};

        use crate::cryptos::rsa::RSA;

        #[test]
        fn demo() {
            let res = "hello world!";
            let data = res.as_bytes();

            let rsa = RSA::new(512).unwrap();
            let sk_pkey = rsa.sk();
            let pk_pkey = rsa.pk();

            let mut signer = Signer::new(MessageDigest::sha256(), &sk_pkey).unwrap();
            assert_eq!(signer.rsa_padding().unwrap(), Padding::PKCS1);
            signer.set_rsa_padding(Padding::PKCS1).unwrap();
            signer.update(data).unwrap();
            let result = signer.sign_to_vec().unwrap();

            let mut verifier = Verifier::new(MessageDigest::sha256(), &sk_pkey).unwrap();
            assert_eq!(verifier.rsa_padding().unwrap(), Padding::PKCS1);
            verifier.update(data).unwrap();
            assert!(verifier.verify(result.as_slice()).unwrap());

            let mut signer = Signer::new(MessageDigest::sha256(), &sk_pkey).unwrap();
            assert_eq!(signer.rsa_padding().unwrap(), Padding::PKCS1);
            signer.set_rsa_padding(Padding::PKCS1).unwrap();
            signer.update(data).unwrap();
            let result = signer.sign_to_vec().unwrap();

            let mut verifier = Verifier::new(MessageDigest::sha256(), &pk_pkey).unwrap();
            assert_eq!(verifier.rsa_padding().unwrap(), Padding::PKCS1);
            verifier.update(data).unwrap();
            assert!(verifier.verify(result.as_slice()).unwrap());
        }

        #[test]
        fn test() {
            let rsa = RSA::new(512).unwrap();
            let res = "hello world!";
            let data = res.as_bytes();

            let en_data = rsa.encrypt_pk(data).unwrap();
            let de_data = rsa.decrypt_sk(en_data.as_slice()).unwrap();
            println!("de_data = {}", String::from_utf8(de_data).unwrap());
            let en_data = rsa.encrypt_sk(data).unwrap();
            let de_data = rsa.decrypt_pk(en_data.as_slice()).unwrap();
            println!("de_data = {}", String::from_utf8(de_data).unwrap());

            let en_data = rsa.encrypt_pk_padding(data, Padding::PKCS1_OAEP).unwrap();
            let de_data = rsa
                .decrypt_sk_padding(en_data.as_slice(), Padding::PKCS1_OAEP)
                .unwrap();
            println!("de_data = {}", String::from_utf8(de_data).unwrap());

            let sign_data = rsa.sign(data).unwrap();
            let res = rsa.verify(data, &sign_data).unwrap();
            println!("res = {}", res);

            let sign_data = rsa
                .sign_cus(data, MessageDigest::sha3_256(), Padding::PKCS1)
                .unwrap();
            let res = rsa
                .verify_cus(data, &sign_data, MessageDigest::sha3_256(), Padding::PKCS1)
                .unwrap();
            println!("res = {}", res);

            let sign_data = rsa
                .sign_cus(data, MessageDigest::sha3_256(), Padding::PKCS1_PSS)
                .unwrap();
            let res = rsa
                .verify_cus(
                    data,
                    &sign_data,
                    MessageDigest::sha3_256(),
                    Padding::PKCS1_PSS,
                )
                .unwrap();
            println!("res = {}", res);
        }
    }

    #[cfg(test)]
    mod generate_pk {
        use openssl::symm::Cipher;

        use crate::cryptos::base64::Base64;
        use crate::cryptos::base64::Base64Encoder;
        use crate::cryptos::rsa::{RSANew, RSANewPass};
        use crate::cryptos::rsa::RSA;

        #[test]
        fn test() {
            let res1 = RSA::generate_pkcs8_pem(512).unwrap();
            let res11 = RSA::generate_pkcs1_pem(512).unwrap();
            let res2 = RSA::generate_pkcs8_pem_string(512).unwrap();
            let res22 = RSA::generate_pkcs1_pem_string(512).unwrap();
            let res3 =
                RSA::generate_pkcs8_pem_pass(512, Cipher::des_ede3_cfb64(), "123321").unwrap();
            let res33 =
                RSA::generate_pkcs1_pem_pass(512, Cipher::des_ede3_cfb64(), "123321").unwrap();
            let res4 =
                RSA::generate_pkcs8_pem_pass(512, Cipher::des_ede3_cfb64(), "123321".to_string())
                    .unwrap();
            let res44 =
                RSA::generate_pkcs1_pem_pass(512, Cipher::des_ede3_cfb64(), "123321".to_string())
                    .unwrap();
            let res5 = RSA::generate_pkcs8_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes().to_vec(),
            )
                .unwrap();
            let res55 = RSA::generate_pkcs1_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes().to_vec(),
            )
                .unwrap();
            let res6 = RSA::generate_pkcs8_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes(),
            )
                .unwrap();
            let res66 = RSA::generate_pkcs1_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes(),
            )
                .unwrap();
            let res7 = RSA::generate_pkcs8_der(512).unwrap();
            let res8 = RSA::generate_pkcs1_der(512).unwrap();
            println!("pem1 v8s 512 = \n{}", String::from_utf8(res1).unwrap());
            println!("pem11 v8s 512 = \n{}", String::from_utf8(res11).unwrap());
            println!("pem2 v8s 512 = \n{}", res2);
            println!("pem22 v8s 512 = \n{}", res22);
            println!(
                "pem3 v8s 512 = \n{}",
                RSA::generate_pkcs8_pem_string(512).unwrap()
            );
            println!("pem4 v8s 512 = \n{}", String::from_utf8(res3).unwrap());
            println!("pem44 v8s 512 = \n{}", String::from_utf8(res33).unwrap());
            println!("pem55 v8s 512 = \n{}", String::from_utf8(res44).unwrap());
            println!("pem5 v8s 512 = \n{}", String::from_utf8(res4).unwrap());
            println!("pem6 v8s 512 = \n{}", res5);
            println!("pem66 v8s 512 = \n{}", res55);
            println!("pem7 v8s 512 = \n{}", res66);
            println!("pem77 v8s 512 = \n{}", res6);
            println!("der3 v8s 512 = \n{}", Base64::encode(res7.clone()));
            println!(
                "der4 v8s 512 = \n{}",
                RSA::generate_pkcs8_der_base64(512).unwrap()
            );
            println!("der3 v8s 512 = \n{}", hex::encode(res7));
            println!("der4 v8s 512 = \n{}", hex::encode(res8));
            println!(
                "der5 v8s 512 = \n{}",
                RSA::generate_pkcs8_der_hex(512).unwrap()
            );
            println!(
                "der6 v8s 512 = \n{}",
                RSA::generate_pkcs1_der_hex(512).unwrap()
            );
        }
    }

    #[cfg(test)]
    mod generate_pk_file {
        use openssl::symm::Cipher;

        use crate::cryptos::base64::Base64;
        use crate::cryptos::base64::Base64Encoder;
        use crate::cryptos::rsa::{RSANewPassStore, RSANewStore};
        use crate::cryptos::rsa::RSA;

        #[test]
        fn test() {
            let res1 =
                RSA::generate_pkcs8_pem(512, "src/test/crypto/rsa/generate/generate1_sk").unwrap();
            let res2 =
                RSA::generate_pkcs8_pem_string(512, "src/test/crypto/rsa/generate/generate2_sk")
                    .unwrap();
            let res3 = RSA::generate_pkcs8_pem_pass(
                512,
                Cipher::des_ede3_cfb64(),
                "123321",
                "src/test/crypto/rsa/generate/generate3_sk",
            )
                .unwrap();
            let res4 = RSA::generate_pkcs8_pem_pass(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".to_string(),
                "src/test/crypto/rsa/generate/generate4_sk",
            )
                .unwrap();
            let res5 = RSA::generate_pkcs8_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes().to_vec(),
                "src/test/crypto/rsa/generate/generate5_sk",
            )
                .unwrap();
            let res6 = RSA::generate_pkcs8_pem_pass_string(
                512,
                Cipher::des_ede3_cfb64(),
                "123321".as_bytes(),
                "src/test/crypto/rsa/generate/generate6_sk",
            )
                .unwrap();
            let res7 =
                RSA::generate_pkcs8_der(512, "src/test/crypto/rsa/generate/generate7_sk").unwrap();
            println!("pem1 v8s 512 = \n{}", String::from_utf8(res1).unwrap());
            println!("pem2 v8s 512 = \n{}", res2);
            println!(
                "pem3 v8s 512 = \n{}",
                RSA::generate_pkcs8_pem_string(512, "src/test/crypto/rsa/generate/generate8_sk")
                    .unwrap()
            );
            println!("pem4 v8s 512 = \n{}", String::from_utf8(res3).unwrap());
            println!("pem5 v8s 512 = \n{}", String::from_utf8(res4).unwrap());
            println!("pem6 v8s 512 = \n{}", res5);
            println!("pem7 v8s 512 = \n{}", res6);
            println!("der3 v8s 512 = \n{}", Base64::encode(res7.clone()));
            println!(
                "der4 v8s 512 = \n{}",
                RSA::generate_pkcs8_der_base64(512, "src/test/crypto/rsa/generate/generate9_sk")
                    .unwrap()
            );
            println!(
                "der5 v8s 512 = \n{}",
                RSA::generate_pkcs1_der_base64(512, "src/test/crypto/rsa/generate/generate99_sk")
                    .unwrap()
            );
            println!("der3 v8s 512 = \n{}", hex::encode(res7));
            println!(
                "der5 v8s 512 = \n{}",
                RSA::generate_pkcs8_der_hex(512, "src/test/crypto/rsa/generate/generate10_sk")
                    .unwrap()
            );
            println!(
                "der6 v8s 512 = \n{}",
                RSA::generate_pkcs1_der_hex(512, "src/test/crypto/rsa/generate/generate1010_sk")
                    .unwrap()
            );
        }
    }

    #[cfg(test)]
    mod store {
        use openssl::symm::Cipher;

        use crate::cryptos::rsa::{RSANew, RSANewPass, RSAStoreKey};
        use crate::cryptos::rsa::RSA;

        #[test]
        fn test() {
            let res1 = RSA::generate_pkcs8_pem(512).unwrap();
            let res2 = RSA::generate_pkcs8_pem_string(512).unwrap();
            let res3 =
                RSA::generate_pkcs8_pem_pass(512, Cipher::des_ede3_cfb64(), "123321").unwrap();
            let res5 = RSA::generate_pkcs8_pem_pass_string(512, Cipher::des_ede3_cfb64(), "123321")
                .unwrap();
            let res6 = RSA::generate_pkcs8_der(512).unwrap();
            let res7 = RSA::generate_pkcs8_der_base64(512).unwrap();
            let res8 = RSA::generate_pkcs8_der_hex(512).unwrap();
            RSA::store(res1, "src/test/crypto/rsa/store/generate1_sk").unwrap();
            RSA::store(res2, "src/test/crypto/rsa/store/generate2_sk").unwrap();
            RSA::store(res3, "src/test/crypto/rsa/store/generate3_sk").unwrap();
            RSA::store(res5, "src/test/crypto/rsa/store/generate5_sk").unwrap();
            RSA::store(res6, "src/test/crypto/rsa/store/generate6_sk").unwrap();
            RSA::store(res7, "src/test/crypto/rsa/store/generate7_sk").unwrap();
            RSA::store(res8, "src/test/crypto/rsa/store/generate8_sk").unwrap();
        }
    }
}

