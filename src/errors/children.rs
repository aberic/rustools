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

use std::fmt::{Display, Formatter, Result};

/// 子类型 Error,实现std::fmt::Debug的trait
#[derive(Debug, Clone)]
pub struct StringError {
    pub error_msg: String,
}

impl Display for StringError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.error_msg)
    }
}

impl std::error::Error for StringError {}

//================== Dir start =====================
#[derive(Debug, Clone)]
pub struct DirExistError;

/// 实现Display的trait，并实现fmt方法
impl Display for DirExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "dir already exist!")
    }
}

/// 实现Error的trait,因为没有子Error,不需要覆盖source()方法
impl std::error::Error for DirExistError {}

#[derive(Debug, Clone)]
pub struct DirNoExistError;

impl Display for DirNoExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "dir not exist!")
    }
}

impl std::error::Error for DirNoExistError {}
//================== Dir end =====================

//================== File start =====================
#[derive(Debug, Clone)]
pub struct FileExistError;

/// 实现Display的trait，并实现fmt方法
impl Display for FileExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "file already exist!")
    }
}

/// 实现Error的trait,因为没有子Error,不需要覆盖source()方法
impl std::error::Error for FileExistError {}

#[derive(Debug, Clone)]
pub struct FileNoExistError;

impl Display for FileNoExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "file not exist!")
    }
}

impl std::error::Error for FileNoExistError {}
//================== File end =====================

//================== Data start =====================
#[derive(Debug, Clone)]
pub struct DataExistError;

/// 实现Display的trait，并实现fmt方法
impl Display for DataExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "data already exist!")
    }
}

/// 实现Error的trait,因为没有子Error,不需要覆盖source()方法
impl std::error::Error for DataExistError {}

#[derive(Debug, Clone)]
pub struct DataNoExistError;

impl Display for DataNoExistError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "data not exist!")
    }
}

impl std::error::Error for DataNoExistError {}
//================== Data end =====================
