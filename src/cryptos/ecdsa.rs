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

use std::path::Path;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};

use crate::cryptos::base64::{Base64Decoder, Base64Encoder};
use crate::cryptos::base64::Base64;
use crate::cryptos::hex::{HexDecoder, HexEncoder};
use crate::cryptos::Hex;
use crate::errors::Errs;
use crate::errors::Results;
use crate::io::file::{FilerReader, FilerWriter};
use crate::io::file::Filer;
use crate::strings::Strings;

pub struct ECDSA {
    sk: PKey<Private>,
    pk: PKey<Public>,
    sk_ec: EcKey<Private>,
    pk_ec: EcKey<Public>,
}

/// base method
impl ECDSA {
    /// 生成ECDSA对象，默认PRIME256V1
    pub fn new() -> Results<ECDSA> {
        let (sk_ec, pk_ec) = generate()?;
        ECDSA::from(sk_ec, pk_ec)
    }

    /// 生成ECDSA对象
    ///
    /// nid OpenSSL对象的数字标识符。
    /// OpenSSL中的对象可以有短名称、长名称和数字标识符(NID)。为方便起见，对象通常在源代码中使用这些数字标识符表示。
    /// 用户通常不需要创建新的' Nid '。
    pub fn new_nid(nid: Nid) -> Results<ECDSA> {
        let (sk_ec, pk_ec) = generate_nid(nid)?;
        ECDSA::from(sk_ec, pk_ec)
    }

    /// 生成ECDSA对象
    pub fn from(sk_ec: EcKey<Private>, pk_ec: EcKey<Public>) -> Results<ECDSA> {
        match PKey::from_ec_key(sk_ec.clone()) {
            Ok(sk) => match PKey::from_ec_key(pk_ec.clone()) {
                Ok(pk) => Ok(ECDSA {
                    sk,
                    pk,
                    sk_ec,
                    pk_ec,
                }),
                Err(err) => return Err(Errs::strs("PKey from_ec_key", err)),
            },
            Err(err) => return Err(Errs::strs("PKey from_ec_key", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_sk(sk: EcKey<Private>) -> Results<ECDSA> {
        let (sk_ec, pk_ec) = generate_pk_from_sk(sk)?;
        ECDSA::from(sk_ec, pk_ec)
    }

    /// 生成ECDSA对象
    pub fn from_sk_pem(sk: Vec<u8>) -> Results<ECDSA> {
        match EcKey::private_key_from_pem(&sk) {
            Ok(sk) => ECDSA::from_sk(sk),
            Err(err) => Err(Errs::strs("EcKey from_sk_pem", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_sk_pem_pkcs8(sk: Vec<u8>) -> Results<ECDSA> {
        match PKey::private_key_from_pem(&sk) {
            Ok(res) => match res.ec_key() {
                Ok(res) => ECDSA::from_sk(res),
                Err(err) => Err(Errs::strs("PKey to ec_key", err)),
            },
            Err(err) => Err(Errs::strs("EcKey from_sk_pem_pkcs8", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_sk_der(sk: Vec<u8>) -> Results<ECDSA> {
        match EcKey::private_key_from_der(&sk) {
            Ok(sk) => ECDSA::from_sk(sk),
            Err(err) => Err(Errs::strs("EcKey from_sk_der", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_sk_bytes(sk: Vec<u8>) -> Results<ECDSA> {
        match ECDSA::from_sk_pem(sk.clone()) {
            Ok(res) => Ok(res),
            Err(_) => match ECDSA::from_sk_der(sk) {
                Ok(res) => Ok(res),
                Err(_) => Err(Errs::str("EcKey private can not load by sk bytes!")),
            },
        }
    }

    /// 生成ECDSA对象
    pub fn from_hex(sk: String, pk: String) -> Results<ECDSA> {
        from_bytes(Hex::decode(sk)?, Hex::decode(pk)?)
    }

    /// 生成ECDSA对象
    pub fn from_hex_nid(sk: String, pk: String, nid: Nid) -> Results<ECDSA> {
        from_bytes_nid(Hex::decode(sk)?, Hex::decode(pk)?, nid)
    }

    /// 生成ECDSA对象
    pub fn from_base64(sk: String, pk: String) -> Results<ECDSA> {
        from_bytes(Base64::decode(sk)?, Base64::decode(pk)?)
    }

    /// 生成ECDSA对象
    pub fn from_base64_nid(sk: String, pk: String, nid: Nid) -> Results<ECDSA> {
        from_bytes_nid(Base64::decode(sk)?, Base64::decode(pk)?, nid)
    }

    /// 生成ECDSA对象
    pub fn from_pem(sk: Vec<u8>, pk: Vec<u8>) -> Results<ECDSA> {
        match EcKey::private_key_from_pem(&sk) {
            Ok(sk_ec) => match EcKey::public_key_from_pem(&pk) {
                Ok(pk_ec) => ECDSA::from(sk_ec, pk_ec),
                Err(err) => Err(Errs::strs("EcKey public_key_from_pem", err)),
            },
            Err(err) => Err(Errs::strs("EcKey private_key_from_pem", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_pem_pkcs8(sk: Vec<u8>, pk: Vec<u8>) -> Results<ECDSA> {
        match PKey::private_key_from_pem(&sk) {
            Ok(res) => match res.ec_key() {
                Ok(sk_ec) => match EcKey::public_key_from_pem(&pk) {
                    Ok(pk_ec) => ECDSA::from(sk_ec, pk_ec),
                    Err(err) => Err(Errs::strs("EcKey public_key_from_pem", err)),
                },
                Err(err) => Err(Errs::strs("PKey to ec_key", err)),
            },
            Err(err) => Err(Errs::strs("EcKey private_key_from_pem", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_der(sk: Vec<u8>, pk: Vec<u8>) -> Results<ECDSA> {
        match EcKey::private_key_from_der(&sk) {
            Ok(sk_ec) => match EcKey::public_key_from_der(&pk) {
                Ok(pk_ec) => ECDSA::from(sk_ec, pk_ec),
                Err(err) => Err(Errs::strs("EcKey public_key_from_der", err)),
            },
            Err(err) => Err(Errs::strs("EcKey private_key_from_der", err)),
        }
    }

    /// 生成ECDSA对象
    pub fn from_sk_pem_file<P: AsRef<Path>>(sk_filepath: P) -> Results<ECDSA> {
        let sk_bytes = Filer::read_bytes(sk_filepath)?;
        ECDSA::from_sk_pem(sk_bytes)
    }

    /// 生成ECDSA对象
    pub fn from_sk_pem_pkcs8_file<P: AsRef<Path>>(sk_filepath: P) -> Results<ECDSA> {
        let sk_bytes = Filer::read_bytes(sk_filepath)?;
        ECDSA::from_sk_pem_pkcs8(sk_bytes)
    }

    /// 生成ECDSA对象
    pub fn from_sk_der_file<P: AsRef<Path>>(sk_filepath: P) -> Results<ECDSA> {
        let sk_bytes = Filer::read_bytes(sk_filepath)?;
        ECDSA::from_sk_der(sk_bytes)
    }

    /// 生成ECDSA对象
    pub fn from_pem_file<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<ECDSA> {
        let sk = Filer::read_bytes(sk_filepath)?;
        let pk = Filer::read_bytes(pk_filepath)?;
        ECDSA::from_pem(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_pem_hex_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<ECDSA> {
        let sk = Hex::decode(Filer::read(sk_filepath)?)?;
        let pk = Hex::decode(Filer::read(pk_filepath)?)?;
        ECDSA::from_pem(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_pem_base64_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<ECDSA> {
        let sk = Base64::decode(Filer::read(sk_filepath)?)?;
        let pk = Base64::decode(Filer::read(pk_filepath)?)?;
        ECDSA::from_pem(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_der_file<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<ECDSA> {
        let sk = Filer::read_bytes(sk_filepath)?;
        let pk = Filer::read_bytes(pk_filepath)?;
        ECDSA::from_der(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_der_hex_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<ECDSA> {
        let sk = Hex::decode(Filer::read(sk_filepath)?)?;
        let pk = Hex::decode(Filer::read(pk_filepath)?)?;
        ECDSA::from_der(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_der_base64_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<ECDSA> {
        let sk = Base64::decode(Filer::read(sk_filepath)?)?;
        let pk = Base64::decode(Filer::read(pk_filepath)?)?;
        ECDSA::from_der(sk, pk)
    }

    /// 生成ECDSA对象
    pub fn from_hex_file<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<ECDSA> {
        let sk = Filer::read(sk_filepath)?;
        let pk = Filer::read(pk_filepath)?;
        from_bytes(Hex::decode(sk)?, Hex::decode(pk)?)
    }

    /// 生成ECDSA对象
    pub fn from_hex_nid_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
        nid: Nid,
    ) -> Results<ECDSA> {
        let sk = Filer::read(sk_filepath)?;
        let pk = Filer::read(pk_filepath)?;
        from_bytes_nid(Hex::decode(sk)?, Hex::decode(pk)?, nid)
    }

    /// 生成ECDSA对象
    pub fn from_base64_file<P: AsRef<Path>>(sk_filepath: P, pk_filepath: P) -> Results<ECDSA> {
        let sk = Filer::read(sk_filepath)?;
        let pk = Filer::read(pk_filepath)?;
        from_bytes(Base64::decode(sk)?, Base64::decode(pk)?)
    }

    /// 生成ECDSA对象
    pub fn from_base64_nid_file<P: AsRef<Path>>(
        sk_filepath: P,
        pk_filepath: P,
        nid: Nid,
    ) -> Results<ECDSA> {
        let sk = Filer::read(sk_filepath)?;
        let pk = Filer::read(pk_filepath)?;
        from_bytes_nid(Base64::decode(sk)?, Base64::decode(pk)?, nid)
    }

    pub fn sk(&self) -> PKey<Private> {
        self.sk.clone()
    }

    pub fn pk(&self) -> PKey<Public> {
        self.pk.clone()
    }

    pub fn sk_ec(&self) -> EcKey<Private> {
        self.sk_ec.clone()
    }

    pub fn pk_ec(&self) -> EcKey<Public> {
        self.pk_ec.clone()
    }
}

/// fmt method
impl ECDSA {
    /// 8ef9639640e5989c559f78dfff4aef383d1340bb71661433ae475e1f52f128e2
    pub fn sk_hex(&self) -> String {
        Hex::encode(self.sk_ec.private_key().to_vec())
    }
    /// jvljlkDlmJxVn3jf/0rvOD0TQLtxZhQzrkdeH1LxKOI=
    pub fn sk_base64(&self) -> String {
        Base64::encode(self.sk_ec.private_key().to_vec())
    }

    pub fn sk_pem(&self) -> Results<Vec<u8>> {
        match self.sk_ec.private_key_to_pem() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn sk_pem_pkcs8(&self) -> Results<Vec<u8>> {
        match self.sk.private_key_to_pem_pkcs8() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem_pkcs8", err)),
        }
    }

    /// -----BEGIN EC PRIVATE KEY-----
    /// MHcCAQEEII75Y5ZA5ZicVZ943/9K7zg9E0C7cWYUM65HXh9S8SjioAoGCCqGSM49
    /// AwEHoUQDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvSqE
    /// m5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END EC PRIVATE KEY-----
    pub fn sk_pem_str(&self) -> Results<String> {
        match self.sk_ec.private_key_to_pem() {
            Ok(res) => Strings::from_utf8(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    /// -----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgek9kS0rTEaJ85kTN
    /// G9U91aqRSsia2W9hmFLHHvottcahRANCAARO2D6g822LBhP0PT/VyKMHbmtzSTvH
    /// RBV+asdJp/ItD8YcN6P4rxCN2CLkkXyUMbDhxIrJfb/7K1lWfcVynGuc
    /// -----END PRIVATE KEY-----
    pub fn sk_pem_pkcs8_str(&self) -> Results<String> {
        match self.sk.private_key_to_pem_pkcs8() {
            Ok(res) => Strings::from_utf8(res),
            Err(err) => Err(Errs::strs("private_key_to_pem_pkcs8", err)),
        }
    }

    /// 2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a4d4863434151454549493735593
    /// 55a41355a6963565a3934332f394b377a673945304337635759554d3635485868395338536a696f416f474343
    /// 7147534d34390a417745486f55514451674145672b586a5834444e4453515a684c6161774e546655586d43413
    /// 249486b4548394265626d4b746354662f524e7046664a765371450a6d35577357494d52797a396a4531455137
    /// 484e4279536c7537513351736878386c513d3d0a2d2d2d2d2d454e442045432050524956415445204b45592d2
    /// d2d2d2d0a
    pub fn sk_pem_hex(&self) -> Results<String> {
        match self.sk_ec.private_key_to_pem() {
            Ok(res) => Ok(Hex::encode(res)),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    /// LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUk3NVk1WkE1WmljVlo5NDMvOUs3emc5RTBD
    /// N2NXWVVNNjVIWGg5UzhTamlvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFZytYalg0RE5EU1FaaExhYXdOVGZVWG1D
    /// QTJJSGtFSDlCZWJtS3RjVGYvUk5wRmZKdlNxRQptNVdzV0lNUnl6OWpFMUVRN0hOQnlTbHU3UTNRc2h4OGxRPT0K
    /// LS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=
    pub fn sk_pem_base64(&self) -> Results<String> {
        match self.sk_ec.private_key_to_pem() {
            Ok(res) => Ok(Base64::encode(res)),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    pub fn sk_der(&self) -> Results<Vec<u8>> {
        match self.sk_ec.private_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    /// 307702010104208ef9639640e5989c559f78dfff4aef383d1340bb71661433ae475e1f52f128e2a00a06082a
    /// 8648ce3d030107a1440342000483e5e35f80cd0d241984b69ac0d4df5179820362079041fd05e6e62ad7137f
    /// f44da457c9bd2a849b95ac588311cb3f63135110ec7341c9296eed0dd0b21c7c95
    pub fn sk_der_hex(&self) -> Results<String> {
        match self.sk_ec.private_key_to_der() {
            Ok(res) => Ok(Hex::encode(res)),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    /// MHcCAQEEII75Y5ZA5ZicVZ943/9K7zg9E0C7cWYUM65HXh9S8SjioAoGCCqGSM49AwEHoUQDQgAEg+XjX4DNDSQZ
    /// hLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvSqEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    pub fn sk_der_base64(&self) -> Results<String> {
        match self.sk_ec.private_key_to_der() {
            Ok(res) => Ok(Base64::encode(res)),
            Err(err) => Err(Errs::strs("private_key_to_pem", err)),
        }
    }

    /// 0383e5e35f80cd0d241984b69ac0d4df5179820362079041fd05e6e62ad7137ff4
    pub fn pk_hex(&self) -> Results<String> {
        let mut ctx = BigNumContext::new().unwrap();
        match self.pk_ec.public_key().to_bytes(
            &self.sk_ec.group(),
            PointConversionForm::COMPRESSED,
            &mut ctx,
        ) {
            Ok(res) => Ok(Hex::encode(res)),
            Err(err) => Err(Errs::strs("public_key to_bytes", err)),
        }
    }

    /// A4Pl41+AzQ0kGYS2msDU31F5ggNiB5BB/QXm5irXE3/0
    pub fn pk_base64(&self) -> Results<String> {
        let mut ctx = BigNumContext::new().unwrap();
        match self.pk_ec.public_key().to_bytes(
            &self.sk_ec.group(),
            PointConversionForm::COMPRESSED,
            &mut ctx,
        ) {
            Ok(res) => Ok(Base64::encode(res)),
            Err(err) => Err(Errs::strs("public_key to_bytes", err)),
        }
    }

    pub fn pk_pem(&self) -> Results<Vec<u8>> {
        match self.pk_ec.public_key_to_pem() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        }
    }

    /// -----BEGIN PUBLIC KEY-----
    /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IH
    /// kEH9BebmKtcTf/RNpFfJvSqEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END PUBLIC KEY-----
    pub fn pk_pem_str(&self) -> Results<String> {
        match self.pk_ec.public_key_to_pem() {
            Ok(res) => Strings::from_utf8(res),
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        }
    }

    /// 2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043
    /// 415159494b6f5a497a6a30444151634451674145672b586a5834444e4453515a684c6161774e546655586d
    /// 43413249480a6b4548394265626d4b746354662f524e7046664a765371456d35577357494d52797a396a45
    /// 31455137484e4279536c7537513351736878386c513d3d0a2d2d2d2d2d454e44205055424c4943204b4559
    /// 2d2d2d2d2d0a
    pub fn pk_pem_hex(&self) -> Results<String> {
        match self.pk_ec.public_key_to_pem() {
            Ok(res) => Ok(Hex::encode(res)),
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        }
    }

    /// LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZy
    /// tYalg0RE5EU1FaaExhYXdOVGZVWG1DQTJJSAprRUg5QmVibUt0Y1RmL1JOcEZmSnZTcUVtNVdzV0lNUnl6OWpF
    /// MUVRN0hOQnlTbHU3UTNRc2h4OGxRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    pub fn pk_pem_base64(&self) -> Results<String> {
        match self.pk_ec.public_key_to_pem() {
            Ok(res) => Ok(Base64::encode(res)),
            Err(err) => Err(Errs::strs("public_key_to_pem", err)),
        }
    }

    pub fn pk_der(&self) -> Results<Vec<u8>> {
        match self.pk_ec.public_key_to_der() {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("public_key_to_der", err)),
        }
    }

    /// 3059301306072a8648ce3d020106082a8648ce3d0301070342000483e5e35f80cd0d241984b69ac0d4df5
    /// 179820362079041fd05e6e62ad7137ff44da457c9bd2a849b95ac588311cb3f63135110ec7341c9296eed
    /// 0dd0b21c7c95
    pub fn pk_der_hex(&self) -> Results<String> {
        match self.pk_ec.public_key_to_der() {
            Ok(res) => Ok(Hex::encode(res)),
            Err(err) => Err(Errs::strs("public_key_to_der", err)),
        }
    }

    /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvS
    /// qEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    pub fn pk_der_base64(&self) -> Results<String> {
        match self.pk_ec.public_key_to_der() {
            Ok(res) => Ok(Base64::encode(res)),
            Err(err) => Err(Errs::strs("public_key_to_der", err)),
        }
    }
}

/// sign method
impl ECDSA {
    pub fn sign(&self, data: &[u8]) -> Results<Vec<u8>> {
        match EcdsaSig::sign(data, &self.sk_ec) {
            Ok(sig) => match sig.to_der() {
                Ok(res) => Ok(res),
                Err(err) => Err(Errs::strs("EcdsaSig to_der", err)),
            },
            Err(err) => Err(Errs::strs("EcdsaSig sign", err)),
        }
    }

    pub fn verify(&self, data: &[u8], der: &[u8]) -> Results<bool> {
        match EcdsaSig::from_der(der) {
            Ok(sig) => match sig.verify(data, &self.pk_ec) {
                Ok(res) => Ok(res),
                Err(err) => Err(Errs::strs("EcdsaSig verify", err)),
            },
            Err(err) => Err(Errs::strs("EcdsaSig from_der", err)),
        }
    }
}

/// store method
impl ECDSA {
    /// 0383e5e35f80cd0d241984b69ac0d4df5179820362079041fd05e6e62ad7137ff4
    pub fn store_hex<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()> {
        let sk_content = self.sk_hex();
        let pk_content = self.pk_hex()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// 23B8WKzfguf7k6N3M/pmzfVYwKYpcUM1FuxfAb3gq3k=
    pub fn store_base64<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()> {
        let sk_content = self.sk_base64();
        let pk_content = self.pk_base64()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// -----BEGIN EC PRIVATE KEY-----
    /// MHcCAQEEII75Y5ZA5ZicVZ943/9K7zg9E0C7cWYUM65HXh9S8SjioAoGCCqGSM49
    /// AwEHoUQDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvSqE
    /// m5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END EC PRIVATE KEY-----
    ///
    /// -----BEGIN PUBLIC KEY-----
    /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IH
    /// kEH9BebmKtcTf/RNpFfJvSqEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END PUBLIC KEY-----
    pub fn store_pem<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()> {
        let sk_content = self.sk_pem()?;
        let pk_content = self.pk_pem()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// -----BEGIN EC PRIVATE KEY-----
    /// MHcCAQEEII75Y5ZA5ZicVZ943/9K7zg9E0C7cWYUM65HXh9S8SjioAoGCCqGSM49
    /// AwEHoUQDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvSqE
    /// m5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END EC PRIVATE KEY-----
    ///
    /// -----BEGIN PUBLIC KEY-----
    /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IH
    /// kEH9BebmKtcTf/RNpFfJvSqEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    /// -----END PUBLIC KEY-----
    pub fn store_pem_pkcs8<P: AsRef<Path>>(
        &self,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<()> {
        let sk_content = self.sk_pem_pkcs8()?;
        let pk_content = self.pk_pem()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// 2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043
    /// 415159494b6f5a497a6a30444151634451674145672b586a5834444e4453515a684c6161774e546655586d
    /// 43413249480a6b4548394265626d4b746354662f524e7046664a765371456d35577357494d52797a396a45
    /// 31455137484e4279536c7537513351736878386c513d3d0a2d2d2d2d2d454e44205055424c4943204b4559
    /// 2d2d2d2d2d0a
    pub fn store_pem_hex<P: AsRef<Path>>(
        &self,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<()> {
        let sk_content = self.sk_pem_hex()?;
        let pk_content = self.pk_pem_hex()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZy
    /// tYalg0RE5EU1FaaExhYXdOVGZVWG1DQTJJSAprRUg5QmVibUt0Y1RmL1JOcEZmSnZTcUVtNVdzV0lNUnl6OWpF
    /// MUVRN0hOQnlTbHU3UTNRc2h4OGxRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    pub fn store_pem_base64<P: AsRef<Path>>(
        &self,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<()> {
        let sk_content = self.sk_pem_base64()?;
        let pk_content = self.pk_pem_base64()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }
    pub fn store_der<P: AsRef<Path>>(&self, sk_filepath: P, pk_filepath: P) -> Results<()> {
        let sk_content = self.sk_der()?;
        let pk_content = self.pk_der()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// 3059301306072a8648ce3d020106082a8648ce3d0301070342000483e5e35f80cd0d241984b69ac0d4df5
    /// 179820362079041fd05e6e62ad7137ff44da457c9bd2a849b95ac588311cb3f63135110ec7341c9296eed
    /// 0dd0b21c7c95
    pub fn store_der_hex<P: AsRef<Path>>(
        &self,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<()> {
        let sk_content = self.sk_der_hex()?;
        let pk_content = self.pk_der_hex()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }

    /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg+XjX4DNDSQZhLaawNTfUXmCA2IHkEH9BebmKtcTf/RNpFfJvS
    /// qEm5WsWIMRyz9jE1EQ7HNBySlu7Q3Qshx8lQ==
    pub fn store_der_base64<P: AsRef<Path>>(
        &self,
        sk_filepath: P,
        pk_filepath: P,
    ) -> Results<()> {
        let sk_content = self.sk_der_base64()?;
        let pk_content = self.pk_der_base64()?;
        let _ = Filer::write_force(sk_filepath, sk_content)?;
        let _ = Filer::write_force(pk_filepath, pk_content)?;
        Ok(())
    }
}

/// 生成ECDSA私钥，默认PRIME256V1
fn generate() -> Results<(EcKey<Private>, EcKey<Public>)> {
    generate_nid(Nid::X9_62_PRIME256V1)
}

/// 生成ECDSA私钥
///
/// nid OpenSSL对象的数字标识符。
/// OpenSSL中的对象可以有短名称、长名称和数字标识符(NID)。为方便起见，对象通常在源代码中使用这些数字标识符表示。
/// 用户通常不需要创建新的' Nid '。
fn generate_nid(nid: Nid) -> Results<(EcKey<Private>, EcKey<Public>)> {
    match EcGroup::from_curve_name(nid) {
        Ok(group) => match EcKey::generate(&group) {
            Ok(sk) => {
                let ec_point_ref = sk.public_key();
                match EcKey::from_public_key(&group, ec_point_ref) {
                    Ok(pk) => Ok((sk, pk)),
                    Err(err) => Err(Errs::strs("from_public_key", err)),
                }
            }
            Err(err) => Err(Errs::strs("generate", err)),
        },
        Err(err) => Err(Errs::strs("from_curve_name", err)),
    }
}

/// 生成ECDSA私钥
///
/// nid OpenSSL对象的数字标识符。
/// OpenSSL中的对象可以有短名称、长名称和数字标识符(NID)。为方便起见，对象通常在源代码中使用这些数字标识符表示。
/// 用户通常不需要创建新的' Nid '。
fn generate_pk_from_sk(sk: EcKey<Private>) -> Results<(EcKey<Private>, EcKey<Public>)> {
    let ec_point_ref = sk.public_key();
    match EcKey::from_public_key(sk.group(), ec_point_ref) {
        Ok(pk) => Ok((sk, pk)),
        Err(err) => Err(Errs::strs("from_public_key", err)),
    }
}

/// 生成ECDSA对象
fn from_bytes(sk_bytes: Vec<u8>, pk_bytes: Vec<u8>) -> Results<ECDSA> {
    from_bytes_nid(sk_bytes, pk_bytes, Nid::X9_62_PRIME256V1)
}

/// 生成ECDSA对象
fn from_bytes_nid(sk_bytes: Vec<u8>, pk_bytes: Vec<u8>, nid: Nid) -> Results<ECDSA> {
    let group = EcGroup::from_curve_name(nid).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let public_key = EcPoint::from_bytes(&group, &pk_bytes, &mut ctx).unwrap();
    let pk_ec = EcKey::from_public_key(&group, &public_key).unwrap();

    match BigNum::from_slice(&sk_bytes) {
        Ok(bn) => match EcKey::from_private_components(&group, &bn, &public_key) {
            Ok(sk_ec) => ECDSA::from(sk_ec, pk_ec),
            Err(err) => Err(Errs::strs("EcKey from_private_components", err)),
        },
        Err(err) => Err(Errs::strs("BigNum from_slice", err)),
    }
}

#[cfg(test)]
mod ecdsa_test {
    #[cfg(test)]
    mod demo {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::ecdsa::EcdsaSig;
        use openssl::error::ErrorStack;
        use openssl::nid::Nid;
        use openssl::pkey::{Private, Public};

        fn get_public_key(
            group: &EcGroup,
            x: &EcKey<Private>,
        ) -> Result<EcKey<Public>, ErrorStack> {
            EcKey::from_public_key(group, x.public_key())
        }

        #[test]
        #[cfg_attr(osslconf = "OPENSSL_NO_EC2M", ignore)]
        fn sign_and_verify() {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1).unwrap();
            let private_key = EcKey::generate(&group).unwrap();
            let public_key = get_public_key(&group, &private_key).unwrap();

            let private_key2 = EcKey::generate(&group).unwrap();
            let public_key2 = get_public_key(&group, &private_key2).unwrap();

            let data = String::from("hello");
            let res = EcdsaSig::sign(data.as_bytes(), &private_key).unwrap();

            // Signature can be verified using the correct data & correct public key
            let verification = res.verify(data.as_bytes(), &public_key).unwrap();
            assert!(verification);

            // Signature will not be verified using the incorrect data but the correct public key
            let verification2 = res
                .verify(String::from("hello2").as_bytes(), &public_key)
                .unwrap();
            assert!(!verification2);

            // Signature will not be verified using the correct data but the incorrect public key
            let verification3 = res.verify(data.as_bytes(), &public_key2).unwrap();
            assert!(!verification3);
        }
    }

    #[cfg(test)]
    mod generate {
        use crate::cryptos::base64::Base64;
        use crate::cryptos::base64::Base64Decoder;
        use crate::cryptos::ecdsa::ECDSA;
        use crate::cryptos::hex::Hex;
        use crate::cryptos::hex::HexDecoder;

        #[test]
        fn test() {
            let ecdsa_pre = ECDSA::new().unwrap();
            let sk = ecdsa_pre.sk_ec();
            let ecdsa1 = ECDSA::from_sk(sk.clone()).unwrap();

            let res = "hello world!";
            let data = res.as_bytes();
            let sig_res = ecdsa_pre.sign(data).unwrap();
            println!(
                "verify = {}",
                ecdsa_pre.verify(data, sig_res.as_slice()).unwrap()
            );
            assert!(ecdsa1.verify(data, sig_res.as_slice()).unwrap());

            let sk_hex = ecdsa1.sk_hex();
            let pk_hex = ecdsa1.pk_hex().unwrap();
            let sk_b64 = ecdsa1.sk_base64();
            let pk_b64 = ecdsa1.pk_base64().unwrap();
            println!("sk str hex = {}", sk_hex.clone());
            println!("sk str b64 = {}", sk_b64.clone());
            println!("sk pem str = {}", ecdsa1.sk_pem_str().unwrap());
            println!("sk pem pkcs8 str = {}", ecdsa1.sk_pem_pkcs8_str().unwrap());
            println!("sk pem hex = {}", ecdsa1.sk_pem_hex().unwrap());
            println!("sk pem b64 = {}", ecdsa1.sk_pem_base64().unwrap());
            println!("sk der hex = {}", ecdsa1.sk_der_hex().unwrap());
            println!("sk der b64 = {}", ecdsa1.sk_der_base64().unwrap());
            println!();
            println!("pk str hex = {}", pk_hex.clone());
            println!("pk str b64 = {}", pk_b64.clone());
            println!("pk pem str = {}", ecdsa1.pk_pem_str().unwrap());
            println!("pk pem hex = {}", ecdsa1.pk_pem_hex().unwrap());
            println!("pk pem b64 = {}", ecdsa1.pk_pem_base64().unwrap());
            println!("pk der hex = {}", ecdsa1.pk_der_hex().unwrap());
            println!("pk der b64 = {}", ecdsa1.pk_der_base64().unwrap());

            let ecdsa2 = ECDSA::from_hex(sk_hex.clone(), pk_hex.clone()).unwrap();
            assert!(ecdsa2.verify(data, sig_res.as_slice()).unwrap());
            println!("ecdsa sk hex = {}", sk_hex.clone());
            println!("ecdsa2 sk hex = {}", ecdsa2.sk_hex());
            println!("ecdsa pk hex = {}", pk_hex.clone());
            println!("ecdsa2 pk hex = {}", ecdsa2.pk_hex().unwrap());
            println!();

            let ecdsa3 = ECDSA::from_base64(sk_b64.clone(), pk_b64.clone()).unwrap();
            assert!(ecdsa3.verify(data, sig_res.as_slice()).unwrap());
            println!("ecdsa sk b64 = {}", sk_b64.clone());
            println!("ecdsa3 sk b64 = {}", ecdsa3.sk_base64());
            println!("ecdsa pk b64 = {}", pk_b64.clone());
            println!("ecdsa3 pk b64 = {}", ecdsa3.pk_base64().unwrap());
            println!();

            let ecdsa4 = ECDSA::from_pem(
                ecdsa1.sk_pem_str().unwrap().into_bytes(),
                ecdsa1.pk_pem_str().unwrap().into_bytes(),
            )
                .unwrap();
            assert!(ecdsa4.verify(data, sig_res.as_slice()).unwrap());
            println!("ecdsa sk pem = {}", sk_b64.clone());
            println!("ecdsa4 sk pem = {}", ecdsa4.sk_base64());
            println!("ecdsa pk pem = {}", pk_b64.clone());
            println!("ecdsa4 pk pem = {}", ecdsa4.pk_base64().unwrap());
            println!();

            let ecdsa5 = ECDSA::from_sk_pem_pkcs8(ecdsa1.sk_pem_pkcs8().unwrap()).unwrap();
            assert!(ecdsa5.verify(data, sig_res.as_slice()).unwrap());
            println!("ecdsa sk pem pkcs8 = {}", sk_b64.clone());
            println!("ecdsa5 sk pem pkcs8 = {}", ecdsa5.sk_base64());
            println!("ecdsa pk pem pkcs8 = {}", pk_b64.clone());
            println!("ecdsa5 pk pem pkcs8 = {}", ecdsa5.pk_base64().unwrap());

            let ecdsa6 = ECDSA::from_der(
                Hex::decode(ecdsa1.sk_der_hex().unwrap()).unwrap(),
                Base64::decode(ecdsa1.pk_der_base64().unwrap()).unwrap(),
            )
                .unwrap();
            assert!(ecdsa6.verify(data, sig_res.as_slice()).unwrap());
            println!("ecdsa sk der = {}", sk_b64.clone());
            println!("ecdsa6 sk der = {}", ecdsa6.sk_base64());
            println!("ecdsa pk der = {}", pk_b64.clone());
            println!("ecdsa6 pk der = {}", ecdsa6.pk_base64().unwrap());
        }

        #[test]
        fn store_test() {
            let ecdsa = ECDSA::new().unwrap();
            ecdsa
                .store_hex(
                    "src/test/crypto/ecdsa/store/hex_sk",
                    "src/test/crypto/ecdsa/store/hex_pk",
                )
                .unwrap();
            ecdsa
                .store_base64(
                    "src/test/crypto/ecdsa/store/base64_sk",
                    "src/test/crypto/ecdsa/store/base64_pk",
                )
                .unwrap();
            ecdsa
                .store_pem(
                    "src/test/crypto/ecdsa/store/pem_str_sk",
                    "src/test/crypto/ecdsa/store/pem_str_pk",
                )
                .unwrap();
            ecdsa
                .store_pem_hex(
                    "src/test/crypto/ecdsa/store/pem_hex_sk",
                    "src/test/crypto/ecdsa/store/pem_hex_pk",
                )
                .unwrap();
            ecdsa
                .store_pem_base64(
                    "src/test/crypto/ecdsa/store/pem_base64_sk",
                    "src/test/crypto/ecdsa/store/pem_base64_pk",
                )
                .unwrap();
            ecdsa
                .store_der(
                    "src/test/crypto/ecdsa/store/der_sk",
                    "src/test/crypto/ecdsa/store/der_pk",
                )
                .unwrap();
            ecdsa
                .store_der_hex(
                    "src/test/crypto/ecdsa/store/der_hex_sk",
                    "src/test/crypto/ecdsa/store/der_hex_pk",
                )
                .unwrap();
            ecdsa
                .store_der_base64(
                    "src/test/crypto/ecdsa/store/der_base64_sk",
                    "src/test/crypto/ecdsa/store/der_base64_pk",
                )
                .unwrap();
        }

        #[test]
        fn load_test() {
            let ecdsa = ECDSA::new().unwrap();
            let res = "hello world!";
            let data = res.as_bytes();
            let sig_res = ecdsa.sign(data).unwrap();
            ecdsa
                .store_hex(
                    "src/test/crypto/ecdsa/load/hex_sk",
                    "src/test/crypto/ecdsa/load/hex_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_hex_file(
                "src/test/crypto/ecdsa/load/hex_sk",
                "src/test/crypto/ecdsa/load/hex_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_base64(
                    "src/test/crypto/ecdsa/load/base64_sk",
                    "src/test/crypto/ecdsa/load/base64_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_base64_file(
                "src/test/crypto/ecdsa/load/base64_sk",
                "src/test/crypto/ecdsa/load/base64_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_pem(
                    "src/test/crypto/ecdsa/load/pem_sk",
                    "src/test/crypto/ecdsa/load/pem_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_pem_file(
                "src/test/crypto/ecdsa/load/pem_sk",
                "src/test/crypto/ecdsa/load/pem_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            let ecdsa_load = ECDSA::from_sk_pem_file("src/test/crypto/ecdsa/load/pem_sk").unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_pem_hex(
                    "src/test/crypto/ecdsa/load/pem_hex_sk",
                    "src/test/crypto/ecdsa/load/pem_hex_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_pem_hex_file(
                "src/test/crypto/ecdsa/load/pem_hex_sk",
                "src/test/crypto/ecdsa/load/pem_hex_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_pem_base64(
                    "src/test/crypto/ecdsa/load/pem_base64_sk",
                    "src/test/crypto/ecdsa/load/pem_base64_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_pem_base64_file(
                "src/test/crypto/ecdsa/load/pem_base64_sk",
                "src/test/crypto/ecdsa/load/pem_base64_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_der(
                    "src/test/crypto/ecdsa/store/der_sk",
                    "src/test/crypto/ecdsa/store/der_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_der_file(
                "src/test/crypto/ecdsa/store/der_sk",
                "src/test/crypto/ecdsa/store/der_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_der_hex(
                    "src/test/crypto/ecdsa/load/der_hex_sk",
                    "src/test/crypto/ecdsa/load/der_hex_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_der_hex_file(
                "src/test/crypto/ecdsa/load/der_hex_sk",
                "src/test/crypto/ecdsa/load/der_hex_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
            ecdsa
                .store_der_base64(
                    "src/test/crypto/ecdsa/load/der_base64_sk",
                    "src/test/crypto/ecdsa/load/der_base64_pk",
                )
                .unwrap();
            let ecdsa_load = ECDSA::from_der_base64_file(
                "src/test/crypto/ecdsa/load/der_base64_sk",
                "src/test/crypto/ecdsa/load/der_base64_pk",
            )
                .unwrap();
            assert!(ecdsa_load.verify(data, sig_res.as_slice()).unwrap());
        }
    }
}

