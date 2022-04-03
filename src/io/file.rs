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

use std::fs;
use std::fs::{File, OpenOptions, read, read_to_string};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::errors::{Errs, Results};
use crate::io::dir::Dir;
use crate::io::dir::DirHandler;
use crate::vectors::Vector;

pub struct Filer;

pub trait FilerNormal {
    /// 获取读`File`
    fn reader<P: AsRef<Path>>(filepath: P) -> Results<File>;

    /// 获取写`File`
    fn writer<P: AsRef<Path>>(filepath: P) -> Results<File>;

    /// 获取追加写`File`
    fn appender<P: AsRef<Path>>(filepath: P) -> Results<File>;

    /// 获取读写`File`
    fn reader_writer<P: AsRef<Path>>(filepath: P) -> Results<File>;

    /// 获取读和追加写`File`
    fn reader_appender<P: AsRef<Path>>(filepath: P) -> Results<File>;
}

pub trait FilerHandler: Sized {
    /// 判断文件是否存在
    fn exist<P: AsRef<Path>>(filepath: P) -> bool;

    /// 创建新文件
    fn touch<P: AsRef<Path>>(filepath: P) -> Results<()>;

    /// 尝试创建新文件，如果存在则返回成功，如果不存在则新建
    fn try_touch<P: AsRef<Path>>(filepath: P) -> Results<()>;

    /// 删除文件，如果不存在该文件则直接返回成功
    fn rm<P: AsRef<Path>>(filepath: P) -> Results<()>;

    /// 指定路径下文件夹名称
    fn name<P: AsRef<Path>>(filepath: P) -> Results<String>;

    /// 拷贝`from`文件至`to`目录下
    fn cp<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()>;

    /// 移动`from`文件至`to`目录下
    fn mv<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()>;

    /// 获取path目录的绝对路径
    ///
    /// 如果存在且为文件夹则报错
    fn absolute<P: AsRef<Path>>(filepath: P) -> Results<String>;

    /// 重命名
    fn rename<P: AsRef<Path>>(from: P, to: P) -> Results<()>;

    /// 父目录
    fn parent<P: AsRef<Path>>(filepath: P) -> Results<String>;
}

pub trait FilerExecutor<T>: Sized {
    /// 向`File`中追加`content`
    fn appends(file: File, content: T) -> Results<()>;

    /// 将`content`在指定`seek`处写入
    fn write_seeks(file: File, seek: u64, content: T) -> Results<()>;
}

pub trait FilerWriter<T>: Sized {
    /// 向file_obj(filepath/file)中写入content，如果file_obj不存在则报错
    fn write<P: AsRef<Path>>(filepath: P, content: T) -> Results<usize>;

    /// 向file_obj(filepath/file)中写入content，如果file_obj不存在则新建
    fn write_force<P: AsRef<Path>>(filepath: P, content: T) -> Results<usize>;

    /// 向file_obj(filepath/file)中追加写content，如果file_obj不存在则报错
    fn append<P: AsRef<Path>>(filepath: P, content: T) -> Results<()>;

    /// 向file_obj(filepath/file)中追加写content，如果file_obj不存在则新建
    fn append_force<P: AsRef<Path>>(filepath: P, content: T) -> Results<()>;

    fn write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: T) -> Results<()>;

    /// 向file_obj(filepath/file)中写入content，如果file_obj不存在则报错
    fn write_file(file: File, content: T) -> Results<usize>;

    /// 向file_obj(filepath/file)中写入content，如果file_obj不存在则新建
    fn write_file_force(file: File, content: T) -> Results<usize>;

    /// 向file_obj(filepath/file)中追加写content，如果file_obj不存在则报错
    fn append_file(file: File, content: T) -> Results<()>;

    /// 向file_obj(filepath/file)中追加写content，如果file_obj不存在则新建
    fn append_file_force(file: File, content: T) -> Results<()>;

    /// 在指定文件中指定位置后覆盖数据
    fn write_file_seek(file: File, seek: u64, content: T) -> Results<()>;
}

pub trait FilerReader: Sized {
    /// 将文件的全部内容读入字符串
    fn read<P: AsRef<Path>>(filepath: P) -> Results<String>;

    /// 将文件的全部内容读入字节数组
    fn read_bytes<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>>;

    /// 读取文件部分内容，从start开始，一直持续读取last长度
    fn read_sub<P: AsRef<Path>>(filepath: P, start: u64, last: usize) -> Results<Vec<u8>>;

    /// 读取文件部分内容，从start开始，一直持续读取last长度
    ///
    /// 如果无法读取该内容，即预期读取坐标超过实际内容长度，则返回期望读取长度的空字节数
    fn read_sub_allow_none<P: AsRef<Path>>(
        filepath: P,
        start: u64,
        last: usize,
    ) -> Results<Vec<u8>>;

    /// 获取文件长度
    fn len<P: AsRef<Path>>(filepath: P) -> Results<u64>;

    /// 读取文件中直到EOF的所有字节，并将它们附加到`string buf`返回
    fn read_file(file: File) -> Results<String>;

    /// 读取文件中直到EOF的所有字节，并返回
    fn read_file_bytes(file: File) -> Results<Vec<u8>>;

    /// 读取文件部分内容，从start开始，一直持续读取last长度
    fn read_file_sub(file: File, start: u64, last: usize) -> Results<Vec<u8>>;

    /// 读取文件部分内容，从start开始，一直持续读取last长度
    ///
    /// 如果无法读取该内容，即预期读取坐标超过实际内容长度，则返回期望读取长度的空字节数组
    fn read_file_sub_allow_none(file: File, start: u64, last: usize) -> Results<Vec<u8>>;

    /// 获取文件长度
    fn len_file(file: File) -> Results<u64>;
}

impl FilerNormal for Filer {
    fn reader<P: AsRef<Path>>(filepath: P) -> Results<File> {
        r_file(filepath)
    }

    fn writer<P: AsRef<Path>>(filepath: P) -> Results<File> {
        w_file(filepath)
    }

    fn appender<P: AsRef<Path>>(filepath: P) -> Results<File> {
        a_file(filepath)
    }

    fn reader_writer<P: AsRef<Path>>(filepath: P) -> Results<File> {
        rw_file(filepath)
    }

    fn reader_appender<P: AsRef<Path>>(filepath: P) -> Results<File> {
        ra_file(filepath)
    }
}

impl FilerHandler for Filer {
    fn exist<P: AsRef<Path>>(filepath: P) -> bool {
        file_exist(&filepath)
    }

    fn touch<P: AsRef<Path>>(filepath: P) -> Results<()> {
        file_touch(&filepath)
    }

    fn try_touch<P: AsRef<Path>>(filepath: P) -> Results<()> {
        file_try_touch(filepath)
    }

    fn rm<P: AsRef<Path>>(filepath: P) -> Results<()> {
        file_remove(filepath)
    }

    fn name<P: AsRef<Path>>(filepath: P) -> Results<String> {
        file_last_name(filepath)
    }

    fn cp<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()> {
        file_copy(file_from_path, file_to_path)
    }

    fn mv<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()> {
        file_move(file_from_path, file_to_path)
    }

    fn absolute<P: AsRef<Path>>(filepath: P) -> Results<String> {
        file_absolute(filepath)
    }

    fn rename<P: AsRef<Path>>(from: P, to: P) -> Results<()> {
        rename(from, to)
    }

    fn parent<P: AsRef<Path>>(filepath: P) -> Results<String> {
        file_parent(filepath)
    }
}

impl FilerExecutor<&[u8]> for Filer {
    fn appends(file: File, content: &[u8]) -> Results<()> {
        file_append(file, content)
    }

    fn write_seeks(file: File, seek: u64, content: &[u8]) -> Results<()> {
        file_write_seek(file, seek, content)
    }
}

impl FilerExecutor<Vec<u8>> for Filer {
    fn appends(file: File, content: Vec<u8>) -> Results<()> {
        file_append(file, content.as_slice())
    }

    fn write_seeks(file: File, seek: u64, content: Vec<u8>) -> Results<()> {
        file_write_seek(file, seek, content.as_slice())
    }
}

impl FilerExecutor<String> for Filer {
    fn appends(file: File, content: String) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn write_seeks(file: File, seek: u64, content: String) -> Results<()> {
        file_write_seek(file, seek, content.as_bytes())
    }
}

impl FilerExecutor<&str> for Filer {
    fn appends(file: File, content: &str) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn write_seeks(file: File, seek: u64, content: &str) -> Results<()> {
        file_write_seek(file, seek, content.as_bytes())
    }
}

impl FilerWriter<&[u8]> for Filer {
    fn write<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<usize> {
        filepath_write(filepath, content)
    }

    fn write_force<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<usize> {
        filepath_write_force(filepath, content)
    }

    fn append<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<()> {
        filepath_append(filepath, content)
    }

    fn append_force<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<()> {
        filepath_append_force(filepath, content)
    }

    fn write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: &[u8]) -> Results<()> {
        filepath_write_seek(filepath, seek, content)
    }

    fn write_file(file: File, content: &[u8]) -> Results<usize> {
        file_write(file, content)
    }

    fn write_file_force(file: File, content: &[u8]) -> Results<usize> {
        file_write(file, content)
    }

    fn append_file(file: File, content: &[u8]) -> Results<()> {
        file_append(file, content)
    }

    fn append_file_force(file: File, content: &[u8]) -> Results<()> {
        file_append(file, content)
    }

    fn write_file_seek(file: File, seek: u64, content: &[u8]) -> Results<()> {
        file_write_seek(file, seek, content)
    }
}

impl FilerWriter<Vec<u8>> for Filer {
    fn write<P: AsRef<Path>>(filepath: P, content: Vec<u8>) -> Results<usize> {
        filepath_write(filepath, content.as_slice())
    }

    fn write_force<P: AsRef<Path>>(filepath: P, content: Vec<u8>) -> Results<usize> {
        filepath_write_force(filepath, content.as_slice())
    }

    fn append<P: AsRef<Path>>(filepath: P, content: Vec<u8>) -> Results<()> {
        filepath_append(filepath, content.as_slice())
    }

    fn append_force<P: AsRef<Path>>(filepath: P, content: Vec<u8>) -> Results<()> {
        filepath_append_force(filepath, content.as_slice())
    }

    fn write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: Vec<u8>) -> Results<()> {
        filepath_write_seek(filepath, seek, content.as_slice())
    }

    fn write_file(file: File, content: Vec<u8>) -> Results<usize> {
        file_write(file, content.as_slice())
    }

    fn write_file_force(file: File, content: Vec<u8>) -> Results<usize> {
        file_write(file, content.as_slice())
    }

    fn append_file(file: File, content: Vec<u8>) -> Results<()> {
        file_append(file, content.as_slice())
    }

    fn append_file_force(file: File, content: Vec<u8>) -> Results<()> {
        file_append(file, content.as_slice())
    }

    fn write_file_seek(file: File, seek: u64, content: Vec<u8>) -> Results<()> {
        file_write_seek(file, seek, content.as_slice())
    }
}

impl FilerWriter<String> for Filer {
    fn write<P: AsRef<Path>>(filepath: P, content: String) -> Results<usize> {
        filepath_write(filepath, content.as_bytes())
    }

    fn write_force<P: AsRef<Path>>(filepath: P, content: String) -> Results<usize> {
        filepath_write_force(filepath, content.as_bytes())
    }

    fn append<P: AsRef<Path>>(filepath: P, content: String) -> Results<()> {
        filepath_append(filepath, content.as_bytes())
    }

    fn append_force<P: AsRef<Path>>(filepath: P, content: String) -> Results<()> {
        filepath_append_force(filepath, content.as_bytes())
    }

    fn write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: String) -> Results<()> {
        filepath_write_seek(filepath, seek, content.as_bytes())
    }

    fn write_file(file: File, content: String) -> Results<usize> {
        file_write(file, content.as_bytes())
    }

    fn write_file_force(file: File, content: String) -> Results<usize> {
        file_write(file, content.as_bytes())
    }

    fn append_file(file: File, content: String) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn append_file_force(file: File, content: String) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn write_file_seek(file: File, seek: u64, content: String) -> Results<()> {
        file_write_seek(file, seek, content.as_bytes())
    }
}

impl FilerWriter<&str> for Filer {
    fn write<P: AsRef<Path>>(filepath: P, content: &str) -> Results<usize> {
        filepath_write(filepath, content.as_bytes())
    }

    fn write_force<P: AsRef<Path>>(filepath: P, content: &str) -> Results<usize> {
        filepath_write_force(filepath, content.as_bytes())
    }

    fn append<P: AsRef<Path>>(filepath: P, content: &str) -> Results<()> {
        filepath_append(filepath, content.as_bytes())
    }

    fn append_force<P: AsRef<Path>>(filepath: P, content: &str) -> Results<()> {
        filepath_append_force(filepath, content.as_bytes())
    }

    fn write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: &str) -> Results<()> {
        filepath_write_seek(filepath, seek, content.as_bytes())
    }

    fn write_file(file: File, content: &str) -> Results<usize> {
        file_write(file, content.as_bytes())
    }

    fn write_file_force(file: File, content: &str) -> Results<usize> {
        file_write(file, content.as_bytes())
    }

    fn append_file(file: File, content: &str) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn append_file_force(file: File, content: &str) -> Results<()> {
        file_append(file, content.as_bytes())
    }

    fn write_file_seek(file: File, seek: u64, content: &str) -> Results<()> {
        file_write_seek(file, seek, content.as_bytes())
    }
}

impl FilerReader for Filer {
    fn read<P: AsRef<Path>>(filepath: P) -> Results<String> {
        filepath_read(filepath)
    }

    fn read_bytes<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
        filepath_reads(filepath)
    }

    fn read_sub<P: AsRef<Path>>(filepath: P, start: u64, last: usize) -> Results<Vec<u8>> {
        filepath_read_sub(filepath, start, last)
    }

    fn read_sub_allow_none<P: AsRef<Path>>(
        filepath: P,
        start: u64,
        last: usize,
    ) -> Results<Vec<u8>> {
        filepath_read_sub_allow_none(filepath, start, last)
    }

    fn len<P: AsRef<Path>>(filepath: P) -> Results<u64> {
        filepath_len(filepath)
    }

    fn read_file(file: File) -> Results<String> {
        file_read(file)
    }

    fn read_file_bytes(file: File) -> Results<Vec<u8>> {
        file_read_bytes(file)
    }

    fn read_file_sub(file: File, start: u64, last: usize) -> Results<Vec<u8>> {
        file_read_sub(file, start, last)
    }

    fn read_file_sub_allow_none(file: File, start: u64, last: usize) -> Results<Vec<u8>> {
        file_read_sub_allow_none(file, start, last)
    }

    fn len_file(file: File) -> Results<u64> {
        file_len(file)
    }
}

/// 判断文件是否存在，如果为文件夹则报错，否则返回判断结果
fn file_exist<P: AsRef<Path>>(filepath: P) -> bool {
    let path_check = Path::new(filepath.as_ref().as_os_str());
    if path_check.exists() {
        if path_check.is_dir() {
            false
        } else {
            true
        }
    } else {
        false
    }
}

/// 创建文件
fn file_touch<P: AsRef<Path>>(filepath: P) -> Results<()> {
    if file_exist(&filepath) {
        Err(Errs::string(format!(
            "file {} already exist!",
            filepath.as_ref().to_str().unwrap()
        )))
    } else {
        let path_check = Path::new(filepath.as_ref().as_os_str());
        match path_check.parent() {
            Some(p) => {
                if !p.exists() {
                    Dir::mk_uncheck(p.to_str().unwrap())?
                }
            }
            None => {}
        }
        match File::create(&filepath) {
            Ok(_) => Ok(()),
            Err(err) => Err(Errs::strings(
                format!("path {} touch error: ", filepath.as_ref().to_str().unwrap()),
                err,
            )),
        }
    }
}

/// 文件父目录
fn file_parent<P: AsRef<Path>>(filepath: P) -> Results<String> {
    let path_check = Path::new(filepath.as_ref().as_os_str());
    match path_check.parent() {
        Some(p) => Ok(p.to_str().unwrap().to_string()),
        None => Err(Errs::str("file's parent is none!")),
    }
}

/// 尝试创建文件，如果存在该文件，则复用该文件
fn file_try_touch<P: AsRef<Path>>(filepath: P) -> Results<()> {
    if file_exist(&filepath) {
        Ok(())
    } else {
        let path_check = Path::new(filepath.as_ref().as_os_str());
        match path_check.parent() {
            Some(p) => {
                if !p.exists() {
                    Dir::mk_uncheck(p.to_str().unwrap())?
                }
            }
            None => {}
        }
        match File::create(&filepath) {
            Ok(_) => Ok(()),
            Err(err) => Err(Errs::strings(
                format!("path {} touch error: ", filepath.as_ref().to_str().unwrap()),
                err,
            )),
        }
    }
}

/// 删除目录
fn file_remove<P: AsRef<Path>>(filepath: P) -> Results<()> {
    if file_exist(&filepath) {
        match fs::remove_file(&filepath) {
            Ok(()) => Ok(()),
            Err(err) => Err(Errs::strings(
                format!(
                    "path {} remove error: ",
                    filepath.as_ref().to_str().unwrap()
                ),
                err,
            )),
        }
    } else {
        Ok(())
    }
}

/// 获取path目录的绝对路径
///
/// 如果存在且为文件夹则报错
fn file_absolute<P: AsRef<Path>>(filepath: P) -> Results<String> {
    if file_exist(&filepath) {
        match fs::canonicalize(&filepath) {
            Ok(path_buf) => Ok(path_buf.to_str().unwrap().to_string()),
            Err(err) => Err(Errs::strings(
                format!(
                    "fs {} canonicalize error: ",
                    filepath.as_ref().to_str().unwrap()
                ),
                err,
            )),
        }
    } else {
        Err(Errs::string(format!(
            "file {} doesn't exist!",
            filepath.as_ref().to_str().unwrap()
        )))
    }
}

/// 判断目录是否存在，如果目录为文件夹则报错，否则返回判断结果
fn file_last_name<P: AsRef<Path>>(filepath: P) -> Results<String> {
    if file_exist(&filepath) {
        Ok(Path::new(filepath.as_ref().as_os_str())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string())
    } else {
        Err(Errs::string(format!(
            "path {} does't exist!",
            filepath.as_ref().to_str().unwrap()
        )))
    }
}

/// 拷贝`from`至`to`
///
/// # Examples
///
/// ```no_run
/// use crate::io::file::{File, FileHandler};
///
/// fn main() -> std::io::Result<()> {
///     File::cp("foo.txt", "bar.txt")?;  // Copy foo.txt to bar.txt
///     Ok(())
/// }
/// ```
fn file_copy<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()> {
    let parent_path = file_parent(&file_to_path)?;
    if !Dir::exist(&parent_path)? {
        Dir::mk(parent_path)?
    }
    match fs::copy(&file_from_path, &file_to_path) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strings(
            format!(
                "copy {} to {} error: ",
                file_from_path.as_ref().to_str().unwrap(),
                file_to_path.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

/// 移动`from`至`to`
///
/// # Examples
///
/// ```no_run
/// use crate::io::file::{File, FileHandler};
///
/// fn main() -> std::io::Result<()> {
///     File::mv("foo.txt", "bar.txt")?;  // Copy foo.txt to bar.txt
///     Ok(())
/// }
/// ```
fn file_move<P: AsRef<Path>>(file_from_path: P, file_to_path: P) -> Results<()> {
    file_copy(&file_from_path, &file_to_path)?;
    file_remove(file_from_path)
}

/// 在指定文件中写入数据
///
/// 返回写入的字节长度
pub fn file_write(mut file: File, content: &[u8]) -> Results<usize> {
    match file.write(content) {
        Ok(size) => Ok(size),
        Err(err) => Err(Errs::strs("file write all", err)),
    }
}

/// 在指定文件中写入数据
///
/// 返回写入的字节长度
pub fn filepath_write<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<usize> {
    match OpenOptions::new().write(true).open(&filepath) {
        Ok(file) => file_write(file, content),
        Err(err) => Err(Errs::strings(
            format!(
                "file {} open when write",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

/// 在指定文件中写入数据
///
/// 返回写入的字节长度
pub fn filepath_write_force<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<usize> {
    if !file_exist(&filepath) {
        file_touch(&filepath)?;
    } else {
        file_remove(&filepath)?;
        file_touch(&filepath)?;
    }
    filepath_write(filepath, content)
}

/// 在指定文件中追加数据
fn filepath_append<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<()> {
    match OpenOptions::new().append(true).open(&filepath) {
        Ok(file) => file_append(file, content),
        Err(err) => Err(Errs::strings(
            format!(
                "file {} open when append",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

/// 在指定文件中追加数据
fn filepath_append_force<P: AsRef<Path>>(filepath: P, content: &[u8]) -> Results<()> {
    if !file_exist(&filepath) {
        file_touch(&filepath)?;
    }
    filepath_append(filepath, content)
}

/// 在指定文件中追加数据
fn file_append(mut file: File, content: &[u8]) -> Results<()> {
    match file.write_all(content) {
        Ok(()) => Ok(()),
        Err(err) => Err(Errs::strs("file write all", err)),
    }
}

/// 在指定文件中指定位置后覆盖数据
fn filepath_write_seek<P: AsRef<Path>>(filepath: P, seek: u64, content: &[u8]) -> Results<()> {
    match OpenOptions::new().write(true).open(&filepath) {
        Ok(file) => file_write_seek(file, seek, content),
        Err(err) => Err(Errs::strings(
            format!(
                "file {} open when write seek",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

/// 在指定文件中指定位置后覆盖数据
fn file_write_seek(mut file: File, seek: u64, content: &[u8]) -> Results<()> {
    match file.seek(SeekFrom::Start(seek)) {
        Ok(_s) => match file.write_all(content) {
            Ok(()) => Ok(()),
            Err(err) => Err(Errs::strs("file write all", err)),
        },
        Err(err) => Err(Errs::strs("file open when write seek", err)),
    }
}

/// 将文件的全部内容读入字符串
fn filepath_read<P: AsRef<Path>>(filepath: P) -> Results<String> {
    match read_to_string(&filepath) {
        Ok(s) => Ok(s),
        Err(err) => Err(Errs::strings(
            format!(
                "file {} read to string",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

fn file_read(mut file: File) -> Results<String> {
    let mut string = String::with_capacity(initial_buffer_size(&file));
    match file.read_to_string(&mut string) {
        Ok(_usize) => Ok(string),
        Err(err) => Err(Errs::strs("file read to string", err)),
    }
}

/// Indicates how large a buffer to pre-allocate before reading the entire file.
fn initial_buffer_size(file: &File) -> usize {
    // Allocate one extra byte so the buffer doesn't need to grow before the
    // final `read` call at the end of the file.  Don't worry about `usize`
    // overflow because reading will fail regardless in that case.
    file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0)
}

/// 将文件的全部内容读入字节数组
fn filepath_reads<P: AsRef<Path>>(filepath: P) -> Results<Vec<u8>> {
    match read(&filepath) {
        Ok(u8s) => Ok(u8s),
        Err(err) => Err(Errs::strings(
            format!(
                "file {} read to string",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

fn file_read_bytes(mut file: File) -> Results<Vec<u8>> {
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_usize) => Ok(buffer),
        Err(err) => Err(Errs::strs("file read to string", err)),
    }
}

/// 读取文件部分内容，从start开始，一直持续读取last长度
fn filepath_read_sub<P: AsRef<Path>>(
    filepath: P,
    start: u64,
    last: usize,
) -> Results<Vec<u8>> {
    match File::open(&filepath) {
        Ok(file) => file_read_sub(file, start, last),
        Err(err) => Err(Errs::strings(
            format!("file {} read sub", filepath.as_ref().to_str().unwrap()),
            err.to_string(),
        )),
    }
}

/// 读取文件部分内容，从start开始，一直持续读取last长度
/// 如果无法读取该内容，即预期读取坐标超过实际内容长度，则返回期望读取长度的空字节数
fn filepath_read_sub_allow_none<P: AsRef<Path>>(
    filepath: P,
    start: u64,
    last: usize,
) -> Results<Vec<u8>> {
    match File::open(&filepath) {
        Ok(file) => file_read_sub_allow_none(file, start, last),
        Err(err) => Err(Errs::strings(
            format!("file {} open", filepath.as_ref().to_str().unwrap()),
            err,
        )),
    }
}

fn filepath_len<P: AsRef<Path>>(filepath: P) -> Results<u64> {
    file_len(r_file(filepath)?)
}

fn file_len(mut file: File) -> Results<u64> {
    match file.seek(SeekFrom::End(0)) {
        Ok(res) => Ok(res),
        Err(err) => Err(Errs::string(err.to_string())),
    }
}

/// 读取文件部分内容，从start开始，一直持续读取last长度
fn file_read_sub(mut file: File, start: u64, last: usize) -> Results<Vec<u8>> {
    let file_len = file.seek(SeekFrom::End(0)).unwrap();
    if file_len < start + last as u64 {
        Err(Errs::string(format!(
            "read sub file {:#?} failed! file_len is {} while start {} and last {}",
            file, file_len, start, last
        )))
    } else {
        file_read_subs_helper(file, start, last)
    }
}

/// 读取文件部分内容，从start开始，一直持续读取last长度
///
/// 如果无法读取该内容，即预期读取坐标超过实际内容长度，则返回期望读取长度的空字节数组
fn file_read_sub_allow_none(mut file: File, start: u64, last: usize) -> Results<Vec<u8>> {
    let file_len = file.seek(SeekFrom::End(0)).unwrap();
    if file_len < start + last as u64 {
        Ok(Vector::create_empty_bytes(last))
    } else {
        file_read_subs_helper(file, start, last)
    }
}

/// 读取文件部分内容，从start开始，一直持续读取last长度
fn file_read_subs_helper(mut file: File, start: u64, last: usize) -> Results<Vec<u8>> {
    match file.seek(SeekFrom::Start(start)) {
        Ok(_u) => {
            if last.eq(&8) {
                let mut buffer = [0u8; 8];
                let mut buf: Vec<u8> = vec![];
                let mut position = 0;
                while position < last {
                    match file.read(&mut buffer) {
                        Ok(_u) => {
                            if last - position >= 8 {
                                for b in buffer.iter() {
                                    buf.push(*b);
                                    position += 1
                                }
                            } else {
                                for b in buffer.iter() {
                                    buf.push(*b);
                                    position += 1;
                                    if last - position <= 0 {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            return Err(Errs::string(format!(
                                "read sub file read failed! error is {}",
                                err
                            )));
                        }
                    }
                }
                Ok(buf)
            } else {
                let mut buffer = [0u8; 1024];
                let mut buf: Vec<u8> = vec![];
                let mut position = 0;
                while position < last {
                    match file.read(&mut buffer) {
                        Ok(_u) => {
                            if last - position >= 1024 {
                                for b in buffer.iter() {
                                    buf.push(*b);
                                    position += 1
                                }
                            } else {
                                for b in buffer.iter() {
                                    buf.push(*b);
                                    position += 1;
                                    if last - position <= 0 {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            return Err(Errs::string(format!(
                                "read sub file read failed! error is {}",
                                err
                            )));
                        }
                    }
                }
                Ok(buf)
            }
        }
        Err(err) => Err(Errs::err(err)),
    }
}

fn rw_file<P: AsRef<Path>>(filepath: P) -> Results<File> {
    match OpenOptions::new().read(true).write(true).open(&filepath) {
        Ok(file) => Ok(file),
        Err(err) => Err(Errs::strings(
            format!(
                "open read&write file {}",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

fn ra_file<P: AsRef<Path>>(filepath: P) -> Results<File> {
    match OpenOptions::new().read(true).append(true).open(&filepath) {
        Ok(file) => Ok(file),
        Err(err) => Err(Errs::strings(
            format!(
                "open read&write file {}",
                filepath.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

fn r_file<P: AsRef<Path>>(filepath: P) -> Results<File> {
    match OpenOptions::new().read(true).open(&filepath) {
        Ok(file) => Ok(file),
        Err(err) => Err(Errs::strings(
            format!("open read file {}", filepath.as_ref().to_str().unwrap()),
            err,
        )),
    }
}

fn w_file<P: AsRef<Path>>(filepath: P) -> Results<File> {
    match OpenOptions::new().write(true).open(&filepath) {
        Ok(file) => Ok(file),
        Err(err) => Err(Errs::strings(
            format!("open write file {}", filepath.as_ref().to_str().unwrap()),
            err,
        )),
    }
}

fn a_file<P: AsRef<Path>>(filepath: P) -> Results<File> {
    match OpenOptions::new().append(true).open(&filepath) {
        Ok(file) => Ok(file),
        Err(err) => Err(Errs::strings(
            format!("open append file {}", filepath.as_ref().to_str().unwrap()),
            err,
        )),
    }
}

fn rename<P: AsRef<Path>>(from: P, to: P) -> Results<()> {
    match std::fs::rename(&from, &to) {
        Ok(_) => Ok(()),
        Err(err) => Err(Errs::strings(
            format!(
                "file rename failed from {} to {}",
                from.as_ref().to_str().unwrap(),
                to.as_ref().to_str().unwrap()
            ),
            err,
        )),
    }
}

#[cfg(test)]
mod file_test {
    use crate::io::file::{FilerHandler, FilerNormal, FilerReader, FilerWriter};
    use crate::io::file::Filer;
    use crate::vectors::{Vector, VectorHandler};

    #[test]
    fn create_file_test() {
        match Filer::touch("src/test/test/dir") {
            Ok(_f) => println!("file_test success"),
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::touch("src/test/test/dir") {
            Ok(_f) => println!("file_test success"),
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::touch("src/test/test/file/a.txt") {
            Ok(_) => {
                // file.write_all("test".as_bytes()).unwrap();
                println!("file_test success")
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::touch("src/test/test/file/a.txt") {
            Ok(_) => println!("file_test success"),
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::touch("src/test/test/file/b.txt") {
            Ok(_) => {
                // file.write_all("test".as_bytes()).unwrap();
                println!("file_test success")
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::touch("src/test/test/file/b.txt") {
            Ok(_) => println!("file_test success"),
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
    }

    #[test]
    fn copy_test() {
        match Filer::touch("src/test/test/file/copy_from.txt") {
            Ok(_) => {
                // file.write_all("copy_from".as_bytes()).unwrap();
                println!("file_test success")
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::cp(
            "src/test/test/file/copy_from.txt",
            "src/test/test/file/copy_to.txt",
        ) {
            Err(err) => println!("file_copy err = {}", err),
            _ => {}
        }
    }

    #[test]
    fn move_test() {
        match Filer::touch("src/test/test/file/move_from.txt") {
            Ok(_) => {
                // file.write_all("move_from".as_bytes()).unwrap();
                println!("file_test success")
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::absolute("src/test/test/file/move_from.txt") {
            Ok(res) => {
                // file.write_all("move_from".as_bytes()).unwrap();
                println!("file absolute = {}", res)
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
        match Filer::mv(
            "src/test/test/file/move_from.txt",
            "src/test/test/file/move_to.txt",
        ) {
            Err(err) => println!("file_move err = {}", err),
            _ => {}
        }
    }

    #[test]
    fn writer_test() {
        match Filer::write("src/test/file/x.txt", vec![0x0b, 0x0c, 0x0d, 0x0e]) {
            Ok(s) => println!("write success with s = {}", s),
            Err(err) => println!("file write err = {}", err),
        }
        match Filer::write_force("src/test/file/y.txt", vec![0x0b, 0x0c, 0x0d, 0x0e]) {
            Ok(s) => println!("write success with s = {}", s),
            Err(err) => println!("file write err = {}", err),
        }
        match Filer::write_force("src/test/file/y.txt", vec![0x01, 0x02, 0x03]) {
            Ok(s) => println!("write success with s = {}", s),
            Err(err) => println!("file write err = {}", err),
        }
    }

    #[test]
    fn writer_append_test() {
        Filer::try_touch("src/test/file/g.txt").unwrap();
        match Filer::append(
            "src/test/file/g.txt",
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            ],
        ) {
            Ok(()) => {
                let vs: Vec<u8> = vec![0x0b, 0x0c, 0x0d, 0x0e];
                match Filer::write_seek("src/test/file/g.txt", 3, vs) {
                    Err(err) => println!("err = {}", err),
                    _ => {}
                }
            }
            Err(err) => println!("err = {}", err),
        }
        match Filer::append(
            "src/test/file/h.txt",
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            ],
        ) {
            Ok(()) => {
                let vs: Vec<u8> = vec![0x0b, 0x0c, 0x0d, 0x0e];
                match Filer::write_seek("src/test/file/g.txt", 3, vs) {
                    Err(err) => println!("err = {}", err),
                    _ => {}
                }
            }
            Err(err) => println!("err = {}", err),
        }
    }

    #[test]
    fn writer_seek_test() {
        Filer::try_touch("src/test/file/seek.txt").unwrap();
        let u8s1 = "hello world!".as_bytes();
        match Filer::write_seek("src/test/file/seek.txt", 100000000, u8s1) {
            Err(err) => println!("err = {}", err),
            _ => {}
        }
        let u8s2 = "success!".as_bytes();
        match Filer::write_seek("src/test/file/seek.txt", 300000000, u8s2) {
            Err(err) => println!("err = {}", err),
            _ => {}
        }
        let u8s3 = "failed!".as_bytes();
        match Filer::write_seek("src/test/file/seek.txt", 150000000, u8s3) {
            Err(err) => println!("err = {}", err),
            _ => {}
        }

        let x1 = Filer::read_sub("src/test/file/seek.txt", 150000000, 7).unwrap();
        println!("x = {}", String::from_utf8(x1).unwrap());
    }

    #[test]
    fn reader_test1() {
        Filer::try_touch("src/test/file/reader.txt").unwrap();
        let u8s1 = "hello world!".as_bytes();
        match Filer::write_seek("src/test/file/reader.txt", 100000000, u8s1) {
            Err(err) => println!("err = {}", err),
            _ => {}
        }
        let x1 = Filer::read_sub_allow_none("src/test/file/reader.txt", 150000000, 7).unwrap();
        println!("x1 is empty = {}", Vector::is_fill(x1.clone()));
        println!("x1 = {}", String::from_utf8(x1).unwrap());

        let x2 = Filer::read_sub_allow_none("src/test/file/reader.txt", 160000000, 8).unwrap();
        println!("x2 is empty = {}", Vector::is_fill(x2.clone()));
        println!("x2 = {}", String::from_utf8(x2).unwrap());

        match Filer::try_touch("src/test/file/read_sub.txt") {
            Err(err) => println!("try_touch err = {}", err.to_string()),
            _ => {}
        }
        match Filer::read_sub("src/test/file/read_sub.txt", 150000000, 7) {
            Ok(x3) => println!("x3 = {}", String::from_utf8(x3).unwrap()),
            Err(err) => println!("read_sub err = {}", err.to_string()),
        }
    }

    #[test]
    fn reader_test2() {
        let s = Filer::read("src/examples/conf.yaml");
        println!("s = {:#?}", s);
    }

    #[test]
    fn reader_test3() {
        let s1 = Filer::read("src/cryptos/mod.rs").unwrap();
        println!("s = {}", s1);
        let file = Filer::reader("src/cryptos/mod.rs").unwrap();
        let s2 = Filer::read_file(file).unwrap();
        println!("s = {}", s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn read_sub_bytes_test1() {
        println!(
            "res1 = {:#?}",
            Filer::read_sub("src/cryptos/base64.rs".to_string(), 448, 8).unwrap()
        );
        println!(
            "res2 = {:#?}",
            Filer::read_sub("src/cryptos/base64.rs".to_string(), 0, 2048).unwrap()
        );
    }

    #[test]
    fn read_sub_bytes_test2() {
        println!(
            "res1 = {:#?}",
            Filer::read_sub("src/cryptos/mod.rs", 448, 8).unwrap()
        );
        let file = Filer::reader("src/cryptos/mod.rs").unwrap();
        println!("res2 = {:#?}", Filer::read_file_sub(file, 448, 8).unwrap());
    }

    #[test]
    fn file_len_test() {
        println!("len1 = {:#?}", Filer::len("src/cryptos/mod.rs").unwrap());
        let file = Filer::reader("src/cryptos/mod.rs").unwrap();
        println!("len2 = {:#?}", Filer::len_file(file).unwrap());
    }

    #[test]
    fn absolute() {
        match Filer::absolute("src/cryptos/mod.rs") {
            Ok(res) => {
                println!("file absolute = {}", res)
            }
            Err(err) => {
                println!("file_test err = {}", err);
            }
        }
    }
}

