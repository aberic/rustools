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
use std::path::Path;

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private, Public};
use openssl::stack::Stack;
use openssl::x509::{
    X509, X509Extension, X509Name, X509NameBuilder, X509NameRef, X509Req,
    X509ReqBuilder, X509StoreContext, X509VerifyResult,
};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::store::X509StoreBuilder;

use crate::errors::Errs;
use crate::errors::Results;
use crate::io::file::{FilerReader, FilerWriter};
use crate::io::file::Filer;

pub struct Cert {
    pub x509: X509,
}

/// sign
impl Cert {
    /// 签发根证书
    ///
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 待签发证书信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_root(
        bits: i32,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        match generate_x509(
            None,
            sk,
            pk,
            SerialNumber::new(bits, msb_ca, odd),
            subject_info,
            version,
            not_before_day,
            not_after_day,
            Extensions {
                basic_constraints: ca_basic_constraints_ext()?,
                key_usage: ca_key_usage_ext()?,
                ext_key_usage: None,
            },
            san,
            message_digest,
        ) {
            Ok(x509) => Ok(Cert { x509 }),
            Err(err) => Err(Errs::strs("create_cert", err)),
        }
    }

    /// 签发128位签名根证书
    ///
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 待签发证书信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_root_128(
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_root(
            128,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发256位签名根证书
    ///
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 待签发证书信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_root_256(
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_root(
            256,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发中间证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate(
        x509: X509,
        bits: i32,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        match generate_x509(
            Some(x509),
            sk,
            pk,
            SerialNumber::new(bits, msb_ca, odd),
            subject_info,
            version,
            not_before_day,
            not_after_day,
            Extensions {
                basic_constraints: ca_basic_constraints_ext()?,
                key_usage: ca_key_usage_ext()?,
                ext_key_usage: None,
            },
            san,
            message_digest,
        ) {
            Ok(x509) => Ok(Cert { x509 }),
            Err(err) => Err(Errs::strs("create_cert", err)),
        }
    }

    /// 签发128位签名中间证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate_128(
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_intermediate(
            x509,
            128,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发256位签名中间证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate_256(
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_intermediate(
            x509,
            256,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发中间证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate_by_csr(
        csr: CSR,
        x509: X509,
        bits: i32,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_intermediate(
            x509,
            bits,
            msb_ca,
            odd,
            sk,
            csr.pk()?,
            csr.x509_req.subject_name(),
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发128位签名中间证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate_128_by_csr(
        csr: CSR,
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_intermediate_by_csr(
            csr,
            x509,
            128,
            msb_ca,
            odd,
            sk,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发256位签名中间证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_intermediate_256_by_csr(
        csr: CSR,
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_intermediate_by_csr(
            csr,
            x509,
            256,
            msb_ca,
            odd,
            sk,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发用户证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * issuer_info 证书的发布者信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user(
        x509: X509,
        bits: i32,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        let basic_constraints: X509Extension;
        match BasicConstraints::new() // 基本约束
            .critical() // 关键
            .build()
        {
            Ok(ext) => basic_constraints = ext,
            Err(err) => return Err(Errs::strs("BasicConstraints build", err)),
        }
        let key_usage: X509Extension;
        match KeyUsage::new() // 密钥使用
            .critical() // 关键
            .non_repudiation()
            .data_encipherment() // 数据加密
            .key_encipherment() // 密钥加密
            .digital_signature() // 数字签名
            .build()
        {
            Ok(ext) => key_usage = ext,
            Err(err) => return Err(Errs::strs("BasicConstraints build", err)),
        }
        let ext_key_usage: Option<X509Extension>;
        match ExtendedKeyUsage::new() // 扩展的密钥使用
            .server_auth() // 服务器认证
            // .client_auth() // 客户端认证
            .build()
        {
            Ok(ext) => ext_key_usage = Some(ext),
            Err(err) => return Err(Errs::strs("BasicConstraints build", err)),
        }
        match generate_x509(
            Some(x509),
            sk,
            pk,
            SerialNumber::new(bits, msb_ca, odd),
            subject_info,
            version,
            not_before_day,
            not_after_day,
            Extensions {
                basic_constraints,
                key_usage,
                ext_key_usage,
            },
            san,
            message_digest,
        ) {
            Ok(x509) => Ok(Cert { x509 }),
            Err(err) => Err(Errs::strs("create_cert", err)),
        }
    }

    /// 签发128位签名用户证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * issuer_info 证书的发布者信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user_128(
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_user(
            x509,
            128,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发256位签名用户证书
    ///
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * pk 待签发证书的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * issuer_info 证书的发布者信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    ///   CN字段用于普通名称，例如DNS名称
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user_256(
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: &X509NameRef,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_user(
            x509,
            256,
            msb_ca,
            odd,
            sk,
            pk,
            subject_info,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发用户证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user_by_csr(
        csr: CSR,
        x509: X509,
        bits: i32,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_user(
            x509,
            bits,
            msb_ca,
            odd,
            sk,
            csr.pk()?,
            csr.x509_req.subject_name(),
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发128位签名用户证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user_128_by_csr(
        csr: CSR,
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_user_by_csr(
            csr,
            x509,
            128,
            msb_ca,
            odd,
            sk,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }

    /// 签发256位签名用户证书
    ///
    /// * csr 证书签名申请
    /// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    /// * sk 签发证书用的私钥
    /// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
    /// * not_before_day 证书上的有效期在指定天之后
    /// * not_after_day 证书上的有效期在指定天之前
    /// * san 主题备用名称扩展对象
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn sign_user_256_by_csr(
        csr: CSR,
        x509: X509,
        msb_ca: MsbOptionCA,
        odd: bool,
        sk: PKey<Private>,
        version: i32,
        not_before_day: u32,
        not_after_day: u32,
        san: Option<SAN>,
        message_digest: MessageDigest,
    ) -> Results<Cert> {
        Cert::sign_user_by_csr(
            csr,
            x509,
            256,
            msb_ca,
            odd,
            sk,
            version,
            not_before_day,
            not_after_day,
            san,
            message_digest,
        )
    }
}

/// save
impl Cert {
    pub fn save_pem<P: AsRef<Path>>(&self, filepath: P) -> Results<()> {
        match self.x509.to_pem() {
            Ok(v8s) => {
                Filer::write_force(filepath, v8s)?;
                Ok(())
            }
            Err(err) => Err(Errs::strs("x509 to_pem", err)),
        }
    }

    pub fn save_der<P: AsRef<Path>>(&self, filepath: P) -> Results<()> {
        match self.x509.to_der() {
            Ok(v8s) => {
                Filer::write_force(filepath, v8s)?;
                Ok(())
            }
            Err(err) => Err(Errs::strs("x509 to_der", err)),
        }
    }
}

/// load
impl Cert {
    pub fn load_pem(bytes: Vec<u8>) -> Results<Cert> {
        match X509::from_pem(bytes.as_slice()) {
            Ok(x509) => Ok(Cert { x509 }),
            Err(err) => Err(Errs::strs("X509 from_pem", err)),
        }
    }

    pub fn load_der(bytes: Vec<u8>) -> Results<Cert> {
        match X509::from_der(bytes.as_slice()) {
            Ok(x509) => Ok(Cert { x509 }),
            Err(err) => Err(Errs::strs("X509 from_der", err)),
        }
    }

    pub fn load_pem_file<P: AsRef<Path>>(filepath: P) -> Results<Cert> {
        match read(filepath) {
            Ok(bytes) => Cert::load_pem(bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }

    pub fn load_der_file<P: AsRef<Path>>(filepath: P) -> Results<Cert> {
        match read(filepath) {
            Ok(bytes) => Cert::load_der(bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }
}

/// stack & verify
impl Cert {
    /// 检查证书是否使用给定的密钥签名
    ///
    /// 一般用于验证指定证书是否由自己签发的
    ///
    /// 只检查签名:不进行其他检查(如证书链有效性)
    pub fn verify(sk: PKey<Private>, x509: X509) -> Results<bool> {
        match x509.verify(&sk) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("x509 verify", err)),
        }
    }

    /// 验证证书`x509`由`pre_x509`签发，证书签发者信息有效性验证
    ///
    /// * pre_x509 签发者证书
    /// * x509 待验证证书
    pub fn verify_cert(pre_x509: X509, x509: X509) -> Results<()> {
        match pre_x509.issued(&x509) {
            X509VerifyResult::OK => Ok(()),
            ver_err => Err(Errs::strs("x509 issued", ver_err)),
        }
    }

    /// 证书链有效性，验证证书签发有效性。
    /// 如果验证成功返回' true '。
    /// 如果证书无效，' error '方法将返回特定的验证错误。
    ///
    /// * pre_x509s 证书链
    /// * x509 待验证证书
    ///
    /// This corresponds to [`X509_verify_cert`].
    ///
    /// [`X509_verify_cert`]:  https://www.openssl.org/docs/man1.0.2/crypto/X509_verify_cert.html
    pub fn verify_cert_chain(pre_x509s: Vec<X509>, x509: X509) -> Results<bool> {
        let chain: Stack<X509>;
        match Stack::new() {
            Ok(res) => chain = res,
            Err(err) => return Err(Errs::strs("Stack new", err)),
        }

        let mut store_builder: X509StoreBuilder;
        match X509StoreBuilder::new() {
            Ok(res) => store_builder = res,
            Err(err) => return Err(Errs::strs("store_builder add_cert", err)),
        }
        for x509 in pre_x509s {
            match store_builder.add_cert(x509) {
                Err(err) => return Err(Errs::strs("store_builder add_cert", err)),
                _ => {}
            }
        }
        let store = store_builder.build();

        let mut context: X509StoreContext;
        match X509StoreContext::new() {
            Ok(res) => context = res,
            Err(err) => return Err(Errs::strs("X509StoreContext new", err)),
        }
        match context.init(&store, &x509, &chain, |c| c.verify_cert()) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("X509StoreContext verify_cert", err)),
        }
    }

    pub fn save_chain_pem<P: AsRef<Path>>(filepath: P, x509s: Vec<X509>) -> Results<()> {
        let mut stacks: Vec<u8> = vec![];
        for x509 in x509s {
            match x509.to_pem() {
                Ok(mut v8s) => {
                    stacks.append(&mut v8s);
                }
                Err(err) => return Err(Errs::strs("x509 to_pem", err)),
            }
        }
        Filer::write_force(filepath, stacks)?;
        Ok(())
    }

    pub fn load_chain_pem<P: AsRef<Path>>(filepath: P) -> Results<Vec<X509>> {
        let bytes = Filer::read_bytes(filepath)?;
        match X509::stack_from_pem(bytes.as_slice()) {
            Ok(v8s) => Ok(v8s),
            Err(err) => return Err(Errs::strs("x509 stack_from_pem", err)),
        }
    }
}

/// Certificate Signing Request的缩写，即证书签名申请。
///
/// 这是要求CA给证书签名的一种正式申请，该申请包含申请证书的实体的公钥及该实体某些信息。
///
/// 该数据将成为证书的一部分。CSR始终使用它携带的公钥所对应的私钥进行签名。
pub struct CSR {
    pub x509_req: X509Req,
}

impl CSR {
    /// 创建证书签名申请
    ///
    /// * pk 申请证书签发请求主体的公钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn create_csr(
        sk: PKey<Private>,
        pk: PKey<Public>,
        subject_info: X509Name,
        message_digest: MessageDigest,
    ) -> Results<X509Req> {
        match X509ReqBuilder::new() {
            Ok(mut req_builder) => match req_builder.set_pubkey(&pk) {
                Ok(()) => match req_builder.set_subject_name(&subject_info) {
                    Ok(()) => match req_builder.sign(&sk, message_digest) {
                        Ok(()) => Ok(req_builder.build()),
                        Err(err) => Err(Errs::strs("sign", err)),
                    },
                    Err(err) => Err(Errs::strs("set_subject_name", err)),
                },
                Err(err) => Err(Errs::strs("set_pubkey", err)),
            },
            Err(err) => Err(Errs::strs("X509ReqBuilder_new", err)),
        }
    }

    /// 创建证书签名申请
    ///
    /// * sk 申请证书签发请求主体的私钥
    /// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
    /// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
    pub fn new(
        sk: PKey<Private>,
        pk: PKey<Public>,
        info: X509Name,
        message_digest: MessageDigest,
    ) -> Results<CSR> {
        Ok(CSR {
            x509_req: CSR::create_csr(sk, pk, info, message_digest)?,
        })
    }

    pub fn pk(&self) -> Results<PKey<Public>> {
        match self.x509_req.public_key() {
            Ok(pk) => Ok(pk),
            Err(err) => Err(Errs::strs("x509_req public_key", err)),
        }
    }

    /// 检查证书签名申请是否使用给定的密钥签名
    ///
    /// 一般用于验证指定证书签名申请是否由自己签发的
    pub fn verify(pk: PKey<Public>, x509_req: X509Req) -> Results<bool> {
        match x509_req.verify(&pk) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("x509_req verify", err)),
        }
    }

    /// Serializes the certificate request to a PEM-encoded PKCS#10 structure.
    ///
    /// The output will have a header of `-----BEGIN CERTIFICATE REQUEST-----`.
    ///
    /// This corresponds to [`PEM_write_bio_X509_REQ`].
    ///
    /// [`PEM_write_bio_X509_REQ`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_X509_REQ.html
    pub fn save_pem<P: AsRef<Path>>(&self, filepath: P) -> Results<()> {
        match self.x509_req.to_pem() {
            Ok(v8s) => {
                Filer::write_force(filepath, v8s)?;
                Ok(())
            }
            Err(err) => Err(Errs::strs("x509 to_pem", err)),
        }
    }

    /// Serializes the certificate request to a DER-encoded PKCS#10 structure.
    ///
    /// This corresponds to [`i2d_X509_REQ`].
    ///
    /// [`i2d_X509_REQ`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_X509_REQ.html
    pub fn save_der<P: AsRef<Path>>(&self, filepath: P) -> Results<()> {
        match self.x509_req.to_der() {
            Ok(v8s) => {
                Filer::write_force(filepath, v8s)?;
                Ok(())
            }
            Err(err) => Err(Errs::strs("x509 to_der", err)),
        }
    }

    pub fn load_pem(bytes: Vec<u8>) -> Results<CSR> {
        match X509Req::from_pem(bytes.as_slice()) {
            Ok(x509_req) => Ok(CSR { x509_req }),
            Err(err) => Err(Errs::strs("X509Req from_pem", err)),
        }
    }

    pub fn load_der(bytes: Vec<u8>) -> Results<CSR> {
        match X509Req::from_der(bytes.as_slice()) {
            Ok(x509_req) => Ok(CSR { x509_req }),
            Err(err) => Err(Errs::strs("X509Req from_der", err)),
        }
    }

    pub fn load_pem_file<P: AsRef<Path>>(filepath: P) -> Results<CSR> {
        match read(filepath) {
            Ok(bytes) => CSR::load_pem(bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }

    pub fn load_der_file<P: AsRef<Path>>(filepath: P) -> Results<CSR> {
        match read(filepath) {
            Ok(bytes) => CSR::load_der(bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }
}

/// 签发证书
///
/// * op_x509 根证书。待签发证书如果自签名则为None，否则不能为None
/// * sk 签发证书用的私钥
/// * pk 待签发证书的公钥
/// * subject_info 证书的主题信息，在构建证书时，使用openssl等命令行工具时通常使用C、ST和O选项。CN字段用于通用名称，比如DNS名称
///   CN字段用于普通名称，例如DNS名称
/// * version 证书版本。版本是零索引的，也就是说，对应于X.509标准版本3的证书应该将“2”传递给该方法。
/// * not_before_day 证书上的有效期在指定天之后
/// * not_after_day 证书上的有效期在指定天之前
/// * is_ca 是否证书颁发机构
/// * extensions 证书扩展对象
/// * san 主题备用名称扩展对象
/// * message_digest 生成签名时摘要算法，如：MessageDigest::sha256()
fn generate_x509(
    op_x509: Option<X509>,
    sk: PKey<Private>,
    pk: PKey<Public>,
    serial_number: SerialNumber,
    subject_info: &X509NameRef,
    version: i32,
    not_before_day: u32,
    not_after_day: u32,
    extensions: Extensions,
    san: Option<SAN>,
    message_digest: MessageDigest,
) -> Result<X509, ErrorStack> {
    // 新建用于构造X509的构造器
    let mut cert_builder = X509::builder()?;
    // 设置证书版本
    cert_builder.set_version(version)?;
    let asn1Integer = serial_number.generate()?;
    // 设置证书的序列号
    cert_builder.set_serial_number(&asn1Integer)?;
    // 设置待签发证书的主题信息
    cert_builder.set_subject_name(subject_info)?;
    // 设置与证书关联的公钥
    cert_builder.set_pubkey(&pk)?;
    // 从现在开始按指定的天数间隔创建一个新的时间
    let not_before = Asn1Time::days_from_now(not_before_day)?;
    // 设置证书上的有效期在指定天之后
    cert_builder.set_not_before(&not_before)?;
    // 从现在开始按指定的天数间隔创建一个新的时间
    let not_after = Asn1Time::days_from_now(not_after_day)?;
    // 设置证书上的有效期在指定天之前
    cert_builder.set_not_after(&not_after)?;
    // 将X509扩展值添加到证书
    cert_builder.append_extension(extensions.basic_constraints)?;
    cert_builder.append_extension(extensions.key_usage)?;
    match extensions.ext_key_usage {
        Some(ext) => cert_builder.append_extension(ext)?,
        _ => {}
    }
    match op_x509 {
        Some(x509) => {
            // 设置签发证书的颁发者信息
            cert_builder.set_issuer_name(x509.subject_name())?;
            // cert_builder.append_extension(
            //     SubjectKeyIdentifier::new() // 主题密钥标识符
            //         // 如果证书是自签名的，则将“发布者”设置为“None”。
            //         .build(&cert_builder.x509v3_context(Some(x509.as_ref()), None))?,
            // )?;
            let auth_key_identifier = AuthorityKeyIdentifier::new() // 授权密钥标识符
                // .keyid(true) // todo 为true则报错
                .issuer(true)
                .build(&cert_builder.x509v3_context(Some(x509.as_ref()), None))?;
            cert_builder.append_extension(auth_key_identifier)?;
            match san {
                Some(s) => {
                    let subject_alternative_name = s.build();
                    let subject_alt_name = subject_alternative_name
                        .build(&cert_builder.x509v3_context(Some(x509.as_ref()), None))?;
                    cert_builder.append_extension(subject_alt_name)?
                }
                _ => {}
            }
        }
        None => {
            // 设置签发证书的颁发者信息
            cert_builder.set_issuer_name(subject_info)?;
            let subject_key_identifier =
                SubjectKeyIdentifier::new() // 主题密钥标识符
                    // 如果证书是自签名的，则将“发布者”设置为“None”。
                    .build(&cert_builder.x509v3_context(None, None))?;
            cert_builder.append_extension(subject_key_identifier)?;
            // cert_builder.append_extension(
            //     AuthorityKeyIdentifier::new() // 授权密钥标识符
            //         .keyid(true)
            //         .build(&cert_builder.x509v3_context(None, None))?,
            // )?;
            match san {
                Some(s) => {
                    let subject_alternative_name = s.build();
                    let subject_alt_name =
                        subject_alternative_name.build(&cert_builder.x509v3_context(None, None))?;
                    cert_builder.append_extension(subject_alt_name)?
                }
                _ => {}
            }
        }
    }
    // 使用私钥签名证书
    cert_builder.sign(&sk, message_digest)?;
    Ok(cert_builder.build())
}

/// 生成证书颁发机构的基本约束扩展
fn ca_basic_constraints_ext() -> Results<X509Extension> {
    match BasicConstraints::new() // 基本约束
        .critical() // 关键
        .ca() // 是证书颁发机构
        .build()
    {
        Ok(ext) => Ok(ext),
        Err(err) => Err(Errs::strs("BasicConstraints build", err)),
    }
}

/// 生成证书颁发机构的密钥使用扩展
fn ca_key_usage_ext() -> Results<X509Extension> {
    match KeyUsage::new() // 密钥使用
        .critical() // 关键
        // .data_encipherment() // 数字签名
        .key_cert_sign() // 密钥证书签名
        .crl_sign() // CRL签名
        .build()
    {
        Ok(ext) => Ok(ext),
        Err(err) => Err(Errs::strs("KeyUsage build", err)),
    }
}

/// 证书主题备用名称：SubjectAlternativeName
pub struct SAN {
    /// DNSNames DNS限制
    pub dns_names: Vec<String>,
    /// EmailAddresses 邮箱地址限制
    pub email_addresses: Vec<String>,
    /// IPAddresses IP地址限制
    pub ip_addresses: Vec<String>,
    /// URIs URL地址限制
    pub uris: Vec<String>,
}

impl SAN {
    /// 主题备用名称
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::x509::extension::SubjectAlternativeName;
    /// use openssl::x509::{X509, X509Extension};
    ///
    /// fn subject_alternative_name() -> X509Extension {
    ///     let mut cert_builder = X509::builder().unwrap();
    ///     SubjectAlternativeName::new() // 主题备用名称
    ///         .dns("example.com")
    ///         .email("info@example.com")
    ///         .build(&cert_builder.x509v3_context(None, None)).unwrap()
    /// }
    /// ```
    pub fn build(&self) -> SubjectAlternativeName {
        let mut subject_alt_name = SubjectAlternativeName::new();
        for dns_name in &self.dns_names {
            subject_alt_name.dns(dns_name.as_str());
        }
        for email_address in &self.email_addresses {
            subject_alt_name.email(email_address.as_str());
        }
        for ip_address in &self.ip_addresses {
            subject_alt_name.ip(ip_address.as_str());
        }
        for uri in &self.uris {
            subject_alt_name.uri(uri.as_str());
        }
        subject_alt_name
    }
}

/// 证书扩展对象
pub struct Extensions {
    /// 基本约束
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::x509::X509Extension;
    /// use openssl::x509::extension::BasicConstraints;
    ///
    /// fn basic_constraints() -> X509Extension {
    ///     BasicConstraints::new() // 基本约束
    ///         .critical() // 关键
    ///         .ca() // 是证书颁发机构
    ///         .build().unwrap()
    /// }
    /// ```
    basic_constraints: X509Extension,
    /// 密钥使用
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::x509::X509Extension;
    /// use openssl::x509::extension::KeyUsage;
    ///
    /// fn key_usage() -> X509Extension {
    ///     KeyUsage::new() // 密钥使用
    ///         .critical() // 关键
    ///         .data_encipherment() // 数据加密
    ///         .key_cert_sign() // 密钥证书签名
    ///         .crl_sign() // CRL签名
    ///         .build().unwrap()
    /// }
    /// ```
    key_usage: X509Extension,
    /// 扩展的密钥使用/指示证书公钥用途扩展
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::x509::X509Extension;
    /// use openssl::x509::extension::ExtendedKeyUsage;
    ///
    /// fn ext_key_usage() -> X509Extension {
    ///     ExtendedKeyUsage::new() // 扩展的密钥使用
    ///         .server_auth() // 服务器认证
    ///         .client_auth() // 客户端认证
    ///         .other("2.999.1")
    ///         .build().unwrap()
    /// }
    /// ```
    ext_key_usage: Option<X509Extension>,
}

impl Extensions {
    /// 新建证书扩展集
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::x509::extension::{SubjectAlternativeName, BasicConstraints, KeyUsage, ExtendedKeyUsage, AuthorityKeyIdentifier};
    /// use openssl::x509::X509Extension;
    ///
    /// fn basic_constraints() -> X509Extension {
    ///     BasicConstraints::new() // 基本约束
    ///         .critical() // 关键
    ///         .ca() // 是证书颁发机构
    ///         .build().unwrap()
    /// }
    ///
    /// fn key_usage() -> X509Extension {
    ///     KeyUsage::new() // 密钥使用
    ///         .critical() // 关键
    ///         .data_encipherment() // 数据加密
    ///         .key_cert_sign() // 密钥证书签名
    ///         .crl_sign() // CRL签名
    ///         .build().unwrap()
    /// }
    ///
    /// fn ext_key_usage() -> X509Extension {
    ///     ExtendedKeyUsage::new() // 扩展的密钥使用
    ///         .server_auth() // 服务器认证
    ///         .client_auth() // 客户端认证
    ///         .other("2.999.1")
    ///         .build().unwrap()
    /// }
    /// ```
    pub fn new(
        basic_constraints: X509Extension,
        key_usage: X509Extension,
        ext_key_usage: Option<X509Extension>,
    ) -> Extensions {
        Extensions {
            basic_constraints,
            key_usage,
            ext_key_usage,
        }
    }
}

/// Options for the most significant bits of a randomly generated `BigNum`.
/// 随机生成' BigNum '的最有效位的选项
pub enum MsbOptionCA {
    /// The most significant bit of the number may be 0.
    /// 该数字的最高有效位可能为0
    One,
    /// The most significant bit of the number must be 1.
    /// 这个数字的最高有效位必须是1
    MaybeZero,
    /// The most significant two bits of the number must be 1.
    /// 这个数字的最有效两位必须是1
    ///
    /// The number of bits in the product of two such numbers will always be exactly twice the
    /// number of bits in the original numbers.
    /// 两个这样的数的乘积的位数总是原始数位数的两倍
    TwoOnes,
}

/// 证书体系序列号
pub struct SerialNumber {
    /// * bits 以比特为单位的数字长度，用于生成一个bits位奇数随机数
    bits: i32,
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    msb_ca: MsbOptionCA,
    /// * odd 如果' true '，则生成的数字为奇数
    odd: bool,
}

impl SerialNumber {
    /// 生成序列号对象
    ///
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    pub fn new(bits: i32, msb_ca: MsbOptionCA, odd: bool) -> SerialNumber {
        SerialNumber { bits, msb_ca, odd }
    }

    /// 生成序列号
    ///
    /// 数字表示法ASN.1中的整数可能包括BigNum、int64或uint64
    ///
    /// * bits 以比特为单位的数字长度
    /// * msb_ca 期望的最高位属性，是随机生成' BigNum '的最有效位的选项
    /// * odd 如果' true '，则生成的数字为奇数
    fn generate(&self) -> Result<Asn1Integer, ErrorStack> {
        // 创建一个值为0的新' BigNum '。
        let mut big_num = BigNum::new()?;
        // 生成一个加密强伪随机' BigNum '
        match self.msb_ca {
            MsbOptionCA::One => big_num.rand(self.bits, MsbOption::ONE, self.odd)?,
            MsbOptionCA::MaybeZero => big_num.rand(self.bits, MsbOption::MAYBE_ZERO, self.odd)?,
            MsbOptionCA::TwoOnes => big_num.rand(self.bits, MsbOption::TWO_ONES, self.odd)?,
        }
        // 返回' Asn1Integer '
        big_num.to_asn1_integer()
    }
}

#[derive(Debug, Clone)]
pub struct X509NameInfo {
    /// ISO国家代码（两位字符），如CN
    country: String,
    /// 公司名称，如George Technology Inc
    organization: Option<String>,
    /// 部门名称	sales Dep
    organizational_unit: Option<String>,
    /// 所在城市，如Tianjin
    locality: Option<String>,
    /// 所在省份，如Tianjin
    province: Option<String>,
    /// 街道地址
    street_address: Option<String>,
    /// 公用名(Common Name)是主机名+域名，比如：www.domain.net<p>
    ///
    /// 数字证书的服务器证书是颁发给某一台主机的，而不是一个域
    ///
    /// 公用名（Common Name）必须与要使用服务器证书的主机的域名完全相同，因为www.domain.com与domain.com是不同的
    common_name: String,
}

impl X509NameInfo {
    pub fn new(common_name: String, country: String) -> Results<X509Name> {
        let xni = X509NameInfo {
            country,
            organization: None,
            organizational_unit: None,
            locality: None,
            province: None,
            street_address: None,
            common_name,
        };
        match xni.build() {
            Ok(x509_name) => Ok(x509_name),
            Err(err) => Err(Errs::strs("X509Name build", err)),
        }
    }

    pub fn new_cus(
        common_name: String,
        country: String,
        organization: Option<String>,
        organizational_unit: Option<String>,
        locality: Option<String>,
        province: Option<String>,
        street_address: Option<String>,
    ) -> Results<X509Name> {
        let xni = X509NameInfo {
            country,
            organization,
            organizational_unit,
            locality,
            province,
            street_address,
            common_name,
        };
        match xni.build() {
            Ok(x509_name) => Ok(x509_name),
            Err(err) => Err(Errs::strs("X509Name build", err)),
        }
    }

    fn build(&self) -> Result<X509Name, ErrorStack> {
        let mut x509_name_builder = X509NameBuilder::new().unwrap();
        x509_name_builder.append_entry_by_nid(Nid::COUNTRYNAME, self.country.as_str())?;
        x509_name_builder.append_entry_by_nid(Nid::COMMONNAME, self.common_name.as_str())?;
        if let Some(res) = self.organization.as_ref() {
            x509_name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, res)?
        }
        if let Some(res) = self.organizational_unit.as_ref() {
            x509_name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, res)?
        }
        if let Some(res) = self.locality.as_ref() {
            x509_name_builder.append_entry_by_nid(Nid::LOCALITYNAME, res)?
        }
        if let Some(res) = self.province.as_ref() {
            x509_name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, res)?
        }
        if let Some(res) = self.street_address.as_ref() {
            x509_name_builder.append_entry_by_nid(Nid::STREETADDRESS, res)?
        }
        Ok(x509_name_builder.build())
    }
}

/// Pkcs #12
pub struct P12 {
    /// 证书。如果为根证书，则`stacks`为空
    x509: X509,
    /// 签发`x509`证书的私钥
    pkey: PKey<Private>,
    /// 证书链
    /// 该链应该包含从`x509`证书到受信任的根证书所需的所有证书
    chain: Vec<X509>,
    /// 密码保护。生成的p12文件提取需要密码
    password: String,
}

pub trait P12Handler<String> {
    /// 构建`P12`对象
    fn new(
        x509: X509,
        pkey: PKey<Private>,
        chain: Vec<X509>,
        password: String,
    ) -> Results<P12>;

    /// 读取`P12`对象
    ///
    /// * bytes `pkcs12.p12`der字节数组
    fn load(password: String, bytes: Vec<u8>) -> Results<P12>;

    /// 读取`P12`对象
    ///
    /// * filepath `pkcs12.p12`文件路径
    fn load_file<P: AsRef<Path>>(password: String, filepath: P) -> Results<P12>;
}

impl P12Handler<&str> for P12 {
    fn new(x509: X509, pkey: PKey<Private>, chain: Vec<X509>, password: &str) -> Results<P12> {
        if chain.len() == 0 || Cert::verify_cert_chain(chain.clone(), x509.clone())? {
            Ok(P12 {
                x509,
                pkey,
                chain,
                password: password.to_string(),
            })
        } else {
            Err(Errs::str("x509 verify cert chain failed!"))
        }
    }

    fn load(password: &str, bytes: Vec<u8>) -> Results<P12> {
        match Pkcs12::from_der(bytes.as_slice()) {
            Ok(res) => match res.parse(password) {
                Ok(res) => {
                    let mut chain: Vec<X509> = vec![];
                    match res.chain {
                        Some(res) => {
                            for x509 in res.into_iter() {
                                chain.push(x509)
                            }
                        }
                        None => {}
                    }
                    Ok(P12 {
                        x509: res.cert,
                        pkey: res.pkey,
                        chain,
                        password: password.to_string(),
                    })
                }
                Err(err) => Err(Errs::strs("Pkcs12 parse", err)),
            },
            Err(err) => Err(Errs::strs("Pkcs12 from_der", err)),
        }
    }

    fn load_file<P: AsRef<Path>>(password: &str, filepath: P) -> Results<P12> {
        match read(filepath) {
            Ok(bytes) => P12::load(password, bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }
}

impl P12Handler<String> for P12 {
    fn new(
        x509: X509,
        pkey: PKey<Private>,
        chain: Vec<X509>,
        password: String,
    ) -> Results<P12> {
        if chain.len() == 0 || Cert::verify_cert_chain(chain.clone(), x509.clone())? {
            Ok(P12 {
                x509,
                pkey,
                chain,
                password,
            })
        } else {
            Err(Errs::str("x509 verify cert chain failed!"))
        }
    }

    fn load(password: String, bytes: Vec<u8>) -> Results<P12> {
        match Pkcs12::from_der(bytes.as_slice()) {
            Ok(res) => match res.parse(password.as_str()) {
                Ok(res) => {
                    let mut chain: Vec<X509> = vec![];
                    match res.chain {
                        Some(res) => {
                            for x509 in res.into_iter() {
                                chain.push(x509)
                            }
                        }
                        None => {}
                    }
                    Ok(P12 {
                        x509: res.cert,
                        pkey: res.pkey,
                        chain,
                        password,
                    })
                }
                Err(err) => Err(Errs::strs("Pkcs12 parse", err)),
            },
            Err(err) => Err(Errs::strs("Pkcs12 from_der", err)),
        }
    }

    fn load_file<P: AsRef<Path>>(password: String, filepath: P) -> Results<P12> {
        match read(filepath) {
            Ok(bytes) => P12::load(password, bytes),
            Err(err) => Err(Errs::strs("read", err)),
        }
    }
}

impl P12 {
    /// 构建`PKCS #12`对象
    pub fn pkcs12(&self) -> Results<Pkcs12> {
        match self
            .x509
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
        {
            Some(name_entry) => match name_entry.data().as_utf8() {
                Ok(openssl_string) => {
                    let friendly_name = openssl_string.as_ref();
                    // 为受保护的pkcs12证书创建新的构建器，使用OpenSSL库的默认值
                    let mut pkcs12_builder = Pkcs12::builder();
                    if !self.chain.is_empty() {
                        let mut chain: Stack<X509>;
                        match Stack::new() {
                            Ok(res) => chain = res,
                            Err(err) => return Err(Errs::strs("Stack new", err)),
                        }
                        for x509 in self.chain.iter() {
                            match chain.push(x509.clone()) {
                                Err(err) => return Err(Errs::strs("chain push", err)),
                                _ => {}
                            }
                        }
                        pkcs12_builder.ca(chain);
                    }
                    match pkcs12_builder.build(
                        self.password.as_str(),
                        friendly_name,
                        self.pkey.as_ref(),
                        self.x509.as_ref(),
                    ) {
                        Ok(res) => Ok(res),
                        Err(err) => Err(Errs::strs("sign pkcs12", err)),
                    }
                }
                Err(err) => Err(Errs::strs("name entry data as utf8", err)),
            },
            None => Err(Errs::str("Cert have no common name!")),
        }
    }

    /// 存储`PKCS #12`对象
    ///
    /// * pkey 生成该证书的私钥
    /// * password 用于加密密钥和证书的密码
    /// * filepath `pkcs12.p12`文件路径
    pub fn save<P: AsRef<Path>>(&self, filepath: P) -> Results<()> {
        let pkcs12 = self.pkcs12()?;
        match pkcs12.to_der() {
            Ok(v8s) => {
                Filer::write_force(filepath, v8s)?;
                Ok(())
            }
            Err(err) => Err(Errs::strs("pkcs12 to_der", err)),
        }
    }
}

#[cfg(test)]
mod ca_test {
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::x509::X509VerifyResult;

    use crate::cryptos::ca::{CSR, MsbOptionCA, P12, P12Handler, SAN, X509NameInfo};
    use crate::cryptos::ca::Cert;
    use crate::cryptos::ecdsa::ECDSA;
    use crate::cryptos::rsa::{RSANewStore, RSAStoreKey};
    use crate::cryptos::rsa::RSA;

    #[test]
    fn cert_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        root.save_pem("src/test/crypto/ca/cert/root.pem.crt")
            .unwrap();
        root.save_der("src/test/crypto/ca/cert/root.der.crt")
            .unwrap();

        let ecdsa_intermediate = ECDSA::new().unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNIntermediate".to_string(),
            "CN".to_string(),
            Some("org inter".to_string()),
            Some("org unit inter".to_string()),
            Some("loc inter".to_string()),
            Some("pro inter".to_string()),
            Some("sa inter".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["inter.cn".to_string()],
            email_addresses: vec!["email@inter.cn".to_string()],
            ip_addresses: vec!["128.0.9.2".to_string()],
            uris: vec!["uri_inter.cn".to_string()],
        });
        let intermediate_cert = Cert::sign_intermediate_128(
            root.x509,
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            ecdsa_intermediate.pk(),
            subject_info.as_ref(),
            2,
            0,
            364,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        intermediate_cert
            .save_pem("src/test/crypto/ca/cert/intermediate.pem.crt")
            .unwrap();
        intermediate_cert
            .save_der("src/test/crypto/ca/cert/intermediate.der.crt")
            .unwrap();

        let rsa_user = RSA::new(512).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNUser".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["user.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let user_cert = Cert::sign_user_256(
            intermediate_cert.x509,
            MsbOptionCA::MaybeZero,
            true,
            ecdsa_intermediate.sk(),
            rsa_user.pk(),
            subject_info.as_ref(),
            2,
            0,
            363,
            san,
            MessageDigest::sha512(),
        )
            .unwrap();
        user_cert
            .save_pem("src/test/crypto/ca/cert/user.pem.crt")
            .unwrap();
        user_cert
            .save_der("src/test/crypto/ca/cert/user.der.crt")
            .unwrap();
    }

    #[test]
    fn cert_verify_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        root.save_pem("src/test/crypto/ca/verify/root.pem.crt")
            .unwrap();
        root.save_der("src/test/crypto/ca/verify/root.der.crt")
            .unwrap();

        let root1 = Cert::load_pem_file("src/test/crypto/ca/verify/root.pem.crt").unwrap();
        let root2 = Cert::load_der_file("src/test/crypto/ca/verify/root.der.crt").unwrap();

        assert!(Cert::verify(rsa_root.sk(), root1.x509).unwrap());
        assert!(Cert::verify(rsa_root.sk(), root2.x509).unwrap());

        let ecdsa_intermediate = ECDSA::new().unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNIntermediate".to_string(),
            "CN".to_string(),
            Some("org inter".to_string()),
            Some("org unit inter".to_string()),
            Some("loc inter".to_string()),
            Some("pro inter".to_string()),
            Some("sa inter".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["inter.cn".to_string()],
            email_addresses: vec!["email@inter.cn".to_string()],
            ip_addresses: vec!["128.0.9.2".to_string()],
            uris: vec!["uri_inter.cn".to_string()],
        });
        let intermediate_cert = Cert::sign_intermediate_128(
            root.x509.clone(),
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            ecdsa_intermediate.pk(),
            subject_info.as_ref(),
            2,
            0,
            364,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        Cert::verify_cert(root.x509.clone(), intermediate_cert.x509.clone()).unwrap();
    }

    #[test]
    fn csr_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        root.save_pem("src/test/crypto/ca/csr/root.pem.crt")
            .unwrap();
        root.save_der("src/test/crypto/ca/csr/root.der.crt")
            .unwrap();

        let rsa_user = RSA::new(512).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNUser".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let csr = CSR::new(
            rsa_user.sk(),
            rsa_user.pk(),
            subject_info,
            MessageDigest::sha256(),
        )
            .unwrap();
        csr.save_pem("src/test/crypto/ca/csr/user.csr.pem.crt")
            .unwrap();
        csr.save_der("src/test/crypto/ca/csr/user.csr.der.crt")
            .unwrap();

        let c1 = CSR::load_pem_file("src/test/crypto/ca/csr/user.csr.pem.crt").unwrap();
        let c2 = CSR::load_der_file("src/test/crypto/ca/csr/user.csr.der.crt").unwrap();
        assert!(CSR::verify(rsa_user.pk(), c1.x509_req).unwrap());
        assert!(CSR::verify(rsa_user.pk(), c2.x509_req).unwrap());

        let c1 = CSR::load_pem_file("src/test/crypto/ca/csr/user.csr.pem.crt").unwrap();
        let c2 = CSR::load_der_file("src/test/crypto/ca/csr/user.csr.der.crt").unwrap();

        let san = Some(SAN {
            dns_names: vec!["user1.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let user_cert1 = Cert::sign_user_128_by_csr(
            c1,
            root.x509.clone(),
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            2,
            0,
            363,
            san,
            MessageDigest::sha512(),
        )
            .unwrap();
        user_cert1
            .save_pem("src/test/crypto/ca/csr/user1.pem.crt")
            .unwrap();
        user_cert1
            .save_der("src/test/crypto/ca/csr/user1.der.crt")
            .unwrap();

        let san = Some(SAN {
            dns_names: vec!["user2.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let user_cert2 = Cert::sign_user_128_by_csr(
            c2,
            root.x509,
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            2,
            0,
            363,
            san,
            MessageDigest::sha512(),
        )
            .unwrap();
        user_cert2
            .save_pem("src/test/crypto/ca/csr/user2.pem.crt")
            .unwrap();
        user_cert2
            .save_der("src/test/crypto/ca/csr/user2.der.crt")
            .unwrap();
    }

    #[test]
    fn cert_stack_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "StackRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        root.save_pem("src/test/crypto/ca/chain/root.pem.crt")
            .unwrap();
        root.save_der("src/test/crypto/ca/chain/root.der.crt")
            .unwrap();

        let ecdsa_intermediate1 = ECDSA::new().unwrap();
        let subject_info = X509NameInfo::new_cus(
            "StackIntermediate1".to_string(),
            "CN".to_string(),
            Some("org inter".to_string()),
            Some("org unit inter".to_string()),
            Some("loc inter".to_string()),
            Some("pro inter".to_string()),
            Some("sa inter".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["inter.cn".to_string()],
            email_addresses: vec!["email@inter.cn".to_string()],
            ip_addresses: vec!["128.0.9.2".to_string()],
            uris: vec!["uri_inter.cn".to_string()],
        });
        let intermediate1_cert = Cert::sign_intermediate_128(
            root.x509.clone(),
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            ecdsa_intermediate1.pk(),
            subject_info.as_ref(),
            2,
            0,
            364,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        intermediate1_cert
            .save_pem("src/test/crypto/ca/chain/intermediate1.pem.crt")
            .unwrap();
        intermediate1_cert
            .save_der("src/test/crypto/ca/chain/intermediate1.der.crt")
            .unwrap();

        let rsa_intermediate2 = RSA::new(512).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "StackIntermediate2".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["user.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let intermediate2_cert = Cert::sign_intermediate_256(
            intermediate1_cert.x509.clone(),
            MsbOptionCA::MaybeZero,
            true,
            ecdsa_intermediate1.sk(),
            rsa_intermediate2.pk(),
            subject_info.as_ref(),
            2,
            0,
            363,
            san,
            MessageDigest::sha512(),
        )
            .unwrap();
        intermediate2_cert
            .save_pem("src/test/crypto/ca/chain/intermediate2.pem.crt")
            .unwrap();
        intermediate2_cert
            .save_der("src/test/crypto/ca/chain/intermediate2.der.crt")
            .unwrap();

        let rsa_intermediate3 = RSA::new(1024).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "StackIntermediate3".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["user.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let intermediate3_cert = Cert::sign_intermediate_256(
            intermediate2_cert.x509.clone(),
            MsbOptionCA::MaybeZero,
            true,
            rsa_intermediate2.sk(),
            rsa_intermediate3.pk(),
            subject_info.as_ref(),
            2,
            0,
            363,
            san,
            MessageDigest::sha256(),
        )
            .unwrap();
        intermediate3_cert
            .save_pem("src/test/crypto/ca/chain/intermediate3.pem.crt")
            .unwrap();
        intermediate3_cert
            .save_der("src/test/crypto/ca/chain/intermediate3.der.crt")
            .unwrap();

        Cert::save_chain_pem(
            "src/test/crypto/ca/chain/chain.pem.crt",
            vec![
                Cert::load_der_file("src/test/crypto/ca/chain/root.der.crt")
                    .unwrap()
                    .x509,
                Cert::load_pem_file("src/test/crypto/ca/chain/intermediate1.pem.crt")
                    .unwrap()
                    .x509,
                Cert::load_der_file("src/test/crypto/ca/chain/intermediate2.der.crt")
                    .unwrap()
                    .x509,
                Cert::load_pem_file("src/test/crypto/ca/chain/intermediate3.pem.crt")
                    .unwrap()
                    .x509,
            ],
        )
            .unwrap();

        let certs = Cert::load_chain_pem("src/test/crypto/ca/chain/chain.pem.crt").unwrap();
        println!("certs len = {}", certs.len());

        let cert_root = certs.get(0).unwrap();
        let inter_root1 = certs.get(1).unwrap();
        let inter_root2 = certs.get(2).unwrap();
        let inter_root3 = certs.get(3).unwrap();
        assert!(Cert::verify_cert_chain(vec![cert_root.clone()], inter_root1.clone()).unwrap());
        assert!(Cert::verify_cert_chain(
            vec![cert_root.clone(), inter_root3.clone()],
            inter_root1.clone(),
        )
            .unwrap());
        assert!(Cert::verify_cert_chain(
            vec![cert_root.clone(), inter_root1.clone()],
            inter_root2.clone(),
        )
            .unwrap());
        assert!(Cert::verify_cert_chain(
            vec![inter_root1.clone(), cert_root.clone()],
            inter_root2.clone(),
        )
            .unwrap());
        assert!(Cert::verify_cert_chain(
            vec![
                cert_root.clone(),
                inter_root1.clone(),
                inter_root2.clone(),
                inter_root3.clone()
            ],
            inter_root3.clone(),
        )
            .unwrap());
        assert!(!Cert::verify_cert_chain(vec![cert_root.clone()], inter_root2.clone()).unwrap());
    }

    #[test]
    fn cert_parse_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        for entry in root.x509.issuer_name().entries() {
            println!("object = {:#?}", entry.object());
            println!("data = {:#?}", entry.data());
        }
        println!(
            "entries = {:#?}",
            root.x509
                .issuer_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .as_utf8()
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn cert_sign_pkcs12_test() {
        let rsa_root = RSA::new(2048).unwrap();
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();
        let san = Some(SAN {
            dns_names: vec!["tt.cn".to_string()],
            email_addresses: vec!["email@tt.cn".to_string()],
            ip_addresses: vec!["128.0.9.1".to_string()],
            uris: vec!["uri_root.cn".to_string()],
        });
        let root = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            true,
            rsa_root.sk(),
            rsa_root.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            san,
            MessageDigest::sha384(),
        )
            .unwrap();
        root.save_pem("src/test/crypto/ca/pkcs12/cert.pem").unwrap();
        RSA::store(
            rsa_root.sk_pkcs1_pem().unwrap(),
            "src/test/crypto/ca/pkcs12/key.pem",
        )
            .unwrap();
        let pkey = rsa_root.sk();
        let p12 = P12::new(root.x509.clone(), pkey.clone(), vec![], "123").unwrap();
        let pkcs12 = p12.pkcs12().unwrap();
        let der = pkcs12.to_der().unwrap();

        let pkcs12 = Pkcs12::from_der(&der).unwrap();
        let parsed = pkcs12.parse("123").unwrap();

        assert_eq!(
            &*parsed.cert.digest(MessageDigest::sha1()).unwrap(),
            &*root.x509.digest(MessageDigest::sha1()).unwrap()
        );
        assert!(parsed.pkey.public_eq(&pkey));

        p12.save("src/test/crypto/ca/pkcs12/root.p12").unwrap();
        let p12 = P12::load_file("123", "src/test/crypto/ca/pkcs12/root.p12").unwrap();
        let pkcs12 = p12.pkcs12().unwrap();
        let parsed = pkcs12.parse("123").unwrap();

        assert_eq!(
            &*parsed.cert.digest(MessageDigest::sha1()).unwrap(),
            &*root.x509.digest(MessageDigest::sha1()).unwrap()
        );
        assert!(parsed.pkey.public_eq(&pkey));
    }

    #[test]
    fn generate_tls_test() {
        generate_rsa_server_tls();
        generate_ec_client_tls();
    }

    fn generate_rsa_server_tls() {
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();

        let server_ca_sk_bytes =
            RSA::generate_pkcs8_pem(3072, "src/test/crypto/ca/tls/server_ca_sk.key").unwrap();
        let server_ca_rsa = RSA::from_bytes(server_ca_sk_bytes).unwrap();
        let server_ca = Cert::sign_root_256(
            MsbOptionCA::MaybeZero,
            false,
            server_ca_rsa.sk(),
            server_ca_rsa.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            None,
            MessageDigest::sha256(),
        )
            .unwrap();
        server_ca
            .save_pem("src/test/crypto/ca/tls/server_ca.pem")
            .unwrap();

        let subject_info_server = X509NameInfo::new_cus(
            "CNUser".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let san_server = Some(SAN {
            dns_names: vec![
                "example.com".to_string(),
                "*.example.com".to_string(),
                "localhost".to_string(),
            ],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["127.0.0.1".to_string(), "0:0:0:0:0:0:0:1".to_string()],
            uris: vec![],
        });
        let server_sk_bytes =
            RSA::generate_pkcs8_pem(2048, "src/test/crypto/ca/tls/server_sk.key").unwrap();
        let server_rsa = RSA::from_bytes(server_sk_bytes).unwrap();
        let server_cert = Cert::sign_user_256(
            server_ca.x509.clone(),
            MsbOptionCA::One,
            true,
            server_ca_rsa.sk(),
            server_rsa.pk(),
            subject_info_server.as_ref(),
            2,
            0,
            363,
            san_server,
            MessageDigest::sha512(),
        )
            .unwrap();
        server_cert
            .save_pem("src/test/crypto/ca/tls/george-server.pem")
            .unwrap();

        match server_ca.x509.issued(server_cert.x509.as_ref()) {
            X509VerifyResult::OK => println!("RSA Certificate verified!"),
            ver_err => println!("Failed to verify certificate: {}", ver_err),
        }
    }

    fn generate_ec_client_tls() {
        let subject_info = X509NameInfo::new_cus(
            "CNRoot".to_string(),
            "CN".to_string(),
            Some("org".to_string()),
            Some("org unit".to_string()),
            Some("loc".to_string()),
            Some("pro".to_string()),
            Some("sa".to_string()),
        )
            .unwrap();

        let client_ca_ec = ECDSA::new().unwrap();
        client_ca_ec
            .store_pem_pkcs8(
                "src/test/crypto/ca/tls/client_ca_sk.key",
                "src/test/crypto/ca/tls/client_ca_pk.pub",
            )
            .unwrap();
        let client_ca = Cert::sign_root_256(
            MsbOptionCA::One,
            true,
            client_ca_ec.sk(),
            client_ca_ec.pk(),
            subject_info.as_ref(),
            2,
            0,
            365,
            None,
            MessageDigest::sha256(),
        )
            .unwrap();
        client_ca
            .save_pem("src/test/crypto/ca/tls/client_ca.pem")
            .unwrap();

        let subject_info_client = X509NameInfo::new_cus(
            "CNUser".to_string(),
            "CN".to_string(),
            Some("org user".to_string()),
            Some("org unit user".to_string()),
            Some("loc user".to_string()),
            Some("pro user".to_string()),
            Some("sa user".to_string()),
        )
            .unwrap();
        let san_client = Some(SAN {
            dns_names: vec!["user.cn".to_string()],
            email_addresses: vec!["email@user.cn".to_string()],
            ip_addresses: vec!["128.0.9.3".to_string()],
            uris: vec!["uri_user.cn".to_string()],
        });
        let client_ec = ECDSA::new().unwrap();
        client_ec
            .store_pem_pkcs8(
                "src/test/crypto/ca/tls/client_sk.key",
                "src/test/crypto/ca/tls/client_pk.pub",
            )
            .unwrap();
        let client_cert = Cert::sign_user_256(
            client_ca.x509.clone(),
            MsbOptionCA::One,
            true,
            client_ca_ec.sk(),
            client_ec.pk(),
            subject_info_client.as_ref(),
            2,
            0,
            363,
            san_client,
            MessageDigest::sha512(),
        )
            .unwrap();
        client_cert
            .save_pem("src/test/crypto/ca/tls/client.pem")
            .unwrap();

        match client_ca.x509.issued(client_cert.x509.as_ref()) {
            X509VerifyResult::OK => println!("EC Certificate verified!"),
            ver_err => println!("Failed to verify certificate: {}", ver_err),
        }
    }
}

