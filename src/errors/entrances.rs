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

use crate::errors::children::{DataExistError, DataNoExistError, DirExistError, DirNoExistError, FileExistError, FileNoExistError, StringError};

trait ToolsStringErr<M, N>: Sized {
    fn string(_: M, _: N) -> Self;
}

trait ToolsString<M>: Sized {
    fn string(_: M) -> Self;
}

/// 索引触发Error,实现std::fmt::Debug的trait
#[derive(Debug, Clone)]
pub enum Error {
    StringError(StringError),
    DirExistError(DirExistError),
    DirNoExistError(DirNoExistError),
    FileExistError(FileExistError),
    FileNoExistError(FileNoExistError),
    DataExistError(DataExistError),
    DataNoExistError(DataNoExistError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            Error::StringError(ref e) => Some(e),
            Error::DirExistError(ref e) => Some(e),
            Error::DirNoExistError(ref e) => Some(e),
            Error::FileExistError(ref e) => Some(e),
            Error::FileNoExistError(ref e) => Some(e),
            Error::DataExistError(ref e) => Some(e),
            Error::DataNoExistError(ref e) => Some(e),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match &self {
            Error::StringError(ref e) => e.fmt(f),
            Error::DirExistError(ref e) => e.fmt(f),
            Error::FileExistError(ref e) => e.fmt(f),
            Error::DirNoExistError(ref e) => e.fmt(f),
            Error::FileNoExistError(ref e) => e.fmt(f),
            Error::DataExistError(ref e) => e.fmt(f),
            Error::DataNoExistError(ref e) => e.fmt(f),
        }
    }
}

impl From<StringError> for Error {
    fn from(s: StringError) -> Self {
        Error::StringError(s)
    }
}

impl From<DirExistError> for Error {
    fn from(s: DirExistError) -> Self {
        Error::DirExistError(s)
    }
}

impl From<DirNoExistError> for Error {
    fn from(s: DirNoExistError) -> Self {
        Error::DirNoExistError(s)
    }
}

impl From<FileExistError> for Error {
    fn from(s: FileExistError) -> Self {
        Error::FileExistError(s)
    }
}

impl From<FileNoExistError> for Error {
    fn from(s: FileNoExistError) -> Self {
        Error::FileNoExistError(s)
    }
}

impl From<DataExistError> for Error {
    fn from(s: DataExistError) -> Self {
        Error::DataExistError(s)
    }
}

impl From<DataNoExistError> for Error {
    fn from(s: DataNoExistError) -> Self {
        Error::DataNoExistError(s)
    }
}

impl<T: ToString> ToolsStringErr<String, T> for Error {
    fn string(msg: String, err: T) -> Self {
        err_strings(msg, err.to_string())
    }
}

impl<T: ToString> ToolsStringErr<&str, T> for Error {
    fn string(msg: &str, err: T) -> Self {
        err_strs(msg, err.to_string())
    }
}

impl ToolsString<String> for Error {
    fn string(msg: String) -> Self {
        err_string(msg)
    }
}

impl ToolsString<&str> for Error {
    fn string(msg: &str) -> Self {
        err_str(msg)
    }
}

pub struct Errs;

impl Errs {
    pub fn err<Err: std::error::Error>(err: Err) -> Error {
        err_string(err.to_string())
    }

    pub fn string(msg: String) -> Error {
        err_string(msg)
    }

    pub fn str(msg: &str) -> Error {
        err_str(msg)
    }

    pub fn strs<Err: ToString>(msg: &str, err: Err) -> Error {
        err_strs(msg, err)
    }

    pub fn strings<Err: ToString>(msg: String, err: Err) -> Error {
        err_strings(msg, err)
    }

    pub fn dir_exist_error() -> Error {
        Error::from(DirExistError)
    }

    pub fn dir_no_exist_error() -> Error {
        Error::from(DirNoExistError)
    }

    pub fn file_exist_error() -> Error {
        Error::from(FileExistError)
    }

    pub fn file_no_exist_error() -> Error {
        Error::from(FileNoExistError)
    }

    pub fn data_exist_error() -> Error {
        Error::from(DataExistError)
    }

    pub fn data_no_exist_error() -> Error {
        Error::from(DataNoExistError)
    }

    pub fn exist_error(msg: &str) -> Error {
        Error::from(err_string(format!("{} already exist!", msg)))
    }

    pub fn no_exist_error(msg: &str) -> Error {
        Error::from(err_string(format!("{} not exist!", msg)))
    }
}

fn err_string(msg: String) -> Error {
    Error::StringError(StringError { error_msg: msg })
}

fn err_str(msg: &str) -> Error {
    Error::StringError(StringError {
        error_msg: msg.to_string(),
    })
}

fn err_strs<Err: ToString>(msg: &str, err: Err) -> Error {
    Error::StringError(StringError {
        error_msg: format!("{}: {}", msg, err.to_string()),
    })
}

fn err_strings<Err: ToString>(msg: String, err: Err) -> Error {
    Error::StringError(StringError {
        error_msg: format!("{}: {}", msg, err.to_string()),
    })
}
