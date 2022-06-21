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

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_yaml::Value;

use crate::Serde;
use crate::errors::{Errs, Results};

#[derive(Clone, Debug)]
pub struct Yaml {
    value: serde_yaml::Value,
}

#[derive(Clone, Debug)]
pub struct YamlArray {
    value: serde_yaml::Value,
}

pub trait YamlHandler {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
            Self: std::marker::Sized;

    fn value(&self) -> Value;

    fn to_string(&self) -> String {
        serde_yaml::to_string(&self.value()).unwrap()
    }

    fn to_vec(&self) -> Vec<u8> {
        serde_yaml::to_vec(&self.value()).unwrap()
    }

    fn to_object<Object>(&self) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_yaml::from_value(self.value()) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("yaml to object", err)),
        }
    }

    fn obj_2_bytes<Object>(value: &Object) -> Results<Vec<u8>>
        where
            Object: ?Sized + Serialize,
    {
        match serde_yaml::to_vec(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn obj_2_string<Object>(value: &Object) -> Results<String>
        where
            Object: ?Sized + Serialize,
    {
        match serde_yaml::to_string(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to string", err)),
        }
    }

    fn obj_2_value<Object>(value: &Object) -> Results<Value>
        where
            Object: ?Sized + Serialize,
    {
        match serde_yaml::to_value(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to string", err)),
        }
    }

    fn bytes_2_obj<Object>(data: &[u8]) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_yaml::from_slice(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("yaml to object", err)),
        }
    }

    fn string_2_obj<Object>(data: &str) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_yaml::from_str(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("yaml to object", err)),
        }
    }

    fn value_2_obj<Object>(data: Value) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_yaml::from_value(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("yaml to object", err)),
        }
    }
}

pub trait YamlNew<T>: Sized {
    fn new(data: T) -> Results<Self>;

    fn from(&mut self, data: T) -> Results<()>;
}

pub trait YamlExec<Param> {
    /// 表示yaml中不存在`param`或者`param`的值为null
    fn has(&self, param: Param) -> bool;

    fn is_string(&self, param: Param) -> bool;

    fn is_u64(&self, param: Param) -> bool;

    fn is_i64(&self, param: Param) -> bool;

    fn is_f64(&self, param: Param) -> bool;

    fn is_bool(&self, param: Param) -> bool;

    fn is_mapping(&self, param: Param) -> bool;

    fn is_sequence(&self, param: Param) -> bool;
}

pub trait YamlGet<Param> {
    fn get_value(&self, param: Param) -> Results<Value>;

    fn get_string(&self, param: Param) -> Results<String>;

    fn get_u64(&self, param: Param) -> Results<u64>;

    fn get_i64(&self, param: Param) -> Results<i64>;

    fn get_f64(&self, param: Param) -> Results<f64>;

    fn get_bool(&self, param: Param) -> Results<bool>;

    fn get_object(&self, param: Param) -> Results<Yaml>;

    fn get_array(&self, param: Param) -> Results<YamlArray>;
}

impl YamlHandler for Yaml {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
    {
        match serde_yaml::to_value(object) {
            Ok(res) => Ok(Yaml { value: res }),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn value(&self) -> Value {
        self.value.clone()
    }
}

impl YamlNew<&[u8]> for Yaml {
    fn new(data: &[u8]) -> Results<Self> {
        Ok(Yaml {
            value: from_slice(data)?,
        })
    }

    fn from(&mut self, data: &[u8]) -> Results<()> {
        self.value = from_slice(data)?;
        Ok(())
    }
}

impl YamlNew<Vec<u8>> for Yaml {
    fn new(data: Vec<u8>) -> Results<Self> {
        Ok(Yaml {
            value: from_slice(data.as_slice())?,
        })
    }

    fn from(&mut self, data: Vec<u8>) -> Results<()> {
        self.value = from_slice(data.as_slice())?;
        Ok(())
    }
}

impl YamlNew<&str> for Yaml {
    fn new(data: &str) -> Results<Self> {
        Ok(Yaml {
            value: from_string(data)?,
        })
    }

    fn from(&mut self, data: &str) -> Results<()> {
        self.value = from_string(data)?;
        Ok(())
    }
}

impl YamlNew<String> for Yaml {
    fn new(data: String) -> Results<Self> {
        Ok(Yaml {
            value: from_string(data.as_str())?,
        })
    }

    fn from(&mut self, data: String) -> Results<()> {
        self.value = from_string(data.as_str())?;
        Ok(())
    }
}

impl YamlNew<Value> for Yaml {
    fn new(value: Value) -> Results<Self> {
        Ok(Yaml { value })
    }

    fn from(&mut self, value: Value) -> Results<()> {
        self.value.clone_from(&value);
        Ok(())
    }
}

impl YamlNew<&Value> for Yaml {
    fn new(value: &Value) -> Results<Self> {
        Ok(Yaml {
            value: value.clone(),
        })
    }

    fn from(&mut self, value: &Value) -> Results<()> {
        self.value.clone_from(value);
        Ok(())
    }
}

impl YamlExec<&str> for Yaml {
    fn has(&self, param: &str) -> bool {
        self.value[param] == Value::Null
    }

    fn is_string(&self, param: &str) -> bool {
        self.value[param].is_string()
    }

    fn is_u64(&self, param: &str) -> bool {
        self.value[param].is_u64()
    }

    fn is_i64(&self, param: &str) -> bool {
        self.value[param].is_i64()
    }

    fn is_f64(&self, param: &str) -> bool {
        self.value[param].is_f64()
    }

    fn is_bool(&self, param: &str) -> bool {
        self.value[param].is_bool()
    }

    fn is_mapping(&self, param: &str) -> bool {
        self.value[param].is_mapping()
    }

    fn is_sequence(&self, param: &str) -> bool {
        self.value[param].is_sequence()
    }
}

impl YamlExec<String> for Yaml {
    fn has(&self, param: String) -> bool {
        self.value[param] != Value::Null
    }

    fn is_string(&self, param: String) -> bool {
        self.value[param].is_string()
    }

    fn is_u64(&self, param: String) -> bool {
        self.value[param].is_u64()
    }

    fn is_i64(&self, param: String) -> bool {
        self.value[param].is_i64()
    }

    fn is_f64(&self, param: String) -> bool {
        self.value[param].is_f64()
    }

    fn is_bool(&self, param: String) -> bool {
        self.value[param].is_bool()
    }

    fn is_mapping(&self, param: String) -> bool {
        self.value[param].is_mapping()
    }

    fn is_sequence(&self, param: String) -> bool {
        self.value[param].is_sequence()
    }
}

impl YamlGet<&str> for Yaml {
    fn get_value(&self, param: &str) -> Results<Value> {
        Ok(self.value[param].clone())
    }

    fn get_string(&self, param: &str) -> Results<String> {
        Serde::param_string(self.value[param].as_str(), param)
    }

    fn get_u64(&self, param: &str) -> Results<u64> {
        Serde::param_u64(self.value[param].as_u64(), param)
    }

    fn get_i64(&self, param: &str) -> Results<i64> {
        Serde::param_i64(self.value[param].as_i64(), param)
    }

    fn get_f64(&self, param: &str) -> Results<f64> {
        Serde::param_f64(self.value[param].as_f64(), param)
    }

    fn get_bool(&self, param: &str) -> Results<bool> {
        Serde::param_bool(self.value[param].as_bool(), param)
    }

    fn get_object(&self, param: &str) -> Results<Yaml> {
        match self.value.get(param) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans object!",
                param
            ))),
        }
    }

    fn get_array(&self, param: &str) -> Results<YamlArray> {
        match self.value.get(param) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans array!",
                param
            ))),
        }
    }
}

impl YamlGet<String> for Yaml {
    fn get_value(&self, param: String) -> Results<Value> {
        Ok(self.value[param].clone())
    }

    fn get_string(&self, param: String) -> Results<String> {
        Serde::param_string(self.value[param.clone()].as_str(), param.as_str())
    }

    fn get_u64(&self, param: String) -> Results<u64> {
        Serde::param_u64(self.value[param.clone()].as_u64(), param.as_str())
    }

    fn get_i64(&self, param: String) -> Results<i64> {
        Serde::param_i64(self.value[param.clone()].as_i64(), param.as_str())
    }

    fn get_f64(&self, param: String) -> Results<f64> {
        Serde::param_f64(self.value[param.clone()].as_f64(), param.as_str())
    }

    fn get_bool(&self, param: String) -> Results<bool> {
        Serde::param_bool(self.value[param.clone()].as_bool(), param.as_str())
    }

    fn get_object(&self, param: String) -> Results<Yaml> {
        match self.value.get(param.clone()) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans object!",
                param
            ))),
        }
    }

    fn get_array(&self, param: String) -> Results<YamlArray> {
        match self.value.get(param.clone()) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans array!",
                param
            ))),
        }
    }
}

impl YamlHandler for YamlArray {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
    {
        match serde_yaml::to_value(object) {
            Ok(res) => Ok(YamlArray { value: res }),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn value(&self) -> Value {
        self.value.clone()
    }
}

impl YamlNew<&[u8]> for YamlArray {
    fn new(data: &[u8]) -> Results<Self> {
        Ok(YamlArray {
            value: from_slice(data)?,
        })
    }

    fn from(&mut self, data: &[u8]) -> Results<()> {
        self.value = from_slice(data)?;
        Ok(())
    }
}

impl YamlNew<Vec<u8>> for YamlArray {
    fn new(data: Vec<u8>) -> Results<Self> {
        Ok(YamlArray {
            value: from_slice(data.as_slice())?,
        })
    }

    fn from(&mut self, data: Vec<u8>) -> Results<()> {
        self.value = from_slice(data.as_slice())?;
        Ok(())
    }
}

impl YamlNew<&str> for YamlArray {
    fn new(data: &str) -> Results<Self> {
        Ok(YamlArray {
            value: from_string(data)?,
        })
    }

    fn from(&mut self, data: &str) -> Results<()> {
        self.value = from_string(data)?;
        Ok(())
    }
}

impl YamlNew<String> for YamlArray {
    fn new(data: String) -> Results<Self> {
        Ok(YamlArray {
            value: from_string(data.as_str())?,
        })
    }

    fn from(&mut self, data: String) -> Results<()> {
        self.value = from_string(data.as_str())?;
        Ok(())
    }
}

impl YamlNew<Value> for YamlArray {
    fn new(value: Value) -> Results<Self> {
        Ok(YamlArray { value })
    }

    fn from(&mut self, value: Value) -> Results<()> {
        self.value.clone_from(&value);
        Ok(())
    }
}

impl YamlNew<&Value> for YamlArray {
    fn new(value: &Value) -> Results<Self> {
        Ok(YamlArray {
            value: value.clone(),
        })
    }

    fn from(&mut self, value: &Value) -> Results<()> {
        self.value.clone_from(value);
        Ok(())
    }
}

impl YamlGet<usize> for YamlArray {
    fn get_value(&self, index: usize) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: usize) -> Results<String> {
        match self.value.get(index) {
            Some(res) => Serde::index_string(res.as_str(), index.to_string().as_str()),
            None => Err(Errs::str("index out of bound while yaml array get string!")),
        }
    }

    fn get_u64(&self, index: usize) -> Results<u64> {
        match self.value.get(index) {
            Some(res) => Serde::index_u64(res.as_u64(), index.to_string().as_str()),
            None => Err(Errs::str("index out of bound while yaml array get u64!")),
        }
    }

    fn get_i64(&self, index: usize) -> Results<i64> {
        match self.value.get(index) {
            Some(res) => Serde::index_i64(res.as_i64(), index.to_string().as_str()),
            None => Err(Errs::str("index out of bound while yaml array get i64!")),
        }
    }

    fn get_f64(&self, index: usize) -> Results<f64> {
        match self.value.get(index) {
            Some(res) => Serde::index_f64(res.as_f64(), index.to_string().as_str()),
            None => Err(Errs::str("index out of bound while yaml array get f64!")),
        }
    }

    fn get_bool(&self, index: usize) -> Results<bool> {
        match self.value.get(index) {
            Some(res) => Serde::index_bool(res.as_bool(), index.to_string().as_str()),
            None => Err(Errs::str("index out of bound while yaml array get bool!")),
        }
    }

    fn get_object(&self, index: usize) -> Results<Yaml> {
        match self.value.get(index) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }

    fn get_array(&self, index: usize) -> Results<YamlArray> {
        match self.value.get(index) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }
}

impl YamlGet<i32> for YamlArray {
    fn get_value(&self, index: i32) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: i32) -> Results<String> {
        self.get_string(index as usize)
    }

    fn get_u64(&self, index: i32) -> Results<u64> {
        self.get_u64(index as usize)
    }

    fn get_i64(&self, index: i32) -> Results<i64> {
        self.get_i64(index as usize)
    }

    fn get_f64(&self, index: i32) -> Results<f64> {
        self.get_f64(index as usize)
    }

    fn get_bool(&self, index: i32) -> Results<bool> {
        self.get_bool(index as usize)
    }

    fn get_object(&self, index: i32) -> Results<Yaml> {
        match self.value.get(index as usize) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::str("index out of bound while yaml array get string!")),
        }
    }

    fn get_array(&self, index: i32) -> Results<YamlArray> {
        match self.value.get(index as usize) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::str("index out of bound while yaml array get string!")),
        }
    }
}

impl YamlGet<u32> for YamlArray {
    fn get_value(&self, index: u32) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: u32) -> Results<String> {
        self.get_string(index as usize)
    }

    fn get_u64(&self, index: u32) -> Results<u64> {
        self.get_u64(index as usize)
    }

    fn get_i64(&self, index: u32) -> Results<i64> {
        self.get_i64(index as usize)
    }

    fn get_f64(&self, index: u32) -> Results<f64> {
        self.get_f64(index as usize)
    }

    fn get_bool(&self, index: u32) -> Results<bool> {
        self.get_bool(index as usize)
    }

    fn get_object(&self, index: u32) -> Results<Yaml> {
        match self.value.get(index as usize) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::str("index out of bound while yaml array get string!")),
        }
    }

    fn get_array(&self, index: u32) -> Results<YamlArray> {
        match self.value.get(index as usize) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::str("index out of bound while yaml array get string!")),
        }
    }
}

impl YamlGet<u64> for YamlArray {
    fn get_value(&self, index: u64) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from yaml array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: u64) -> Results<String> {
        self.get_string(index as usize)
    }

    fn get_u64(&self, index: u64) -> Results<u64> {
        self.get_u64(index as usize)
    }

    fn get_i64(&self, index: u64) -> Results<i64> {
        self.get_i64(index as usize)
    }

    fn get_f64(&self, index: u64) -> Results<f64> {
        self.get_f64(index as usize)
    }

    fn get_bool(&self, index: u64) -> Results<bool> {
        self.get_bool(index as usize)
    }

    fn get_object(&self, index: u64) -> Results<Yaml> {
        match self.value.get(index as usize) {
            Some(res) => Yaml::new(res),
            None => Err(Errs::str("index out of bound while yaml array get bool!")),
        }
    }

    fn get_array(&self, index: u64) -> Results<YamlArray> {
        match self.value.get(index as usize) {
            Some(res) => YamlArray::new(res),
            None => Err(Errs::str("index out of bound while yaml array get bool!")),
        }
    }
}

impl Default for Yaml {
    fn default() -> Yaml {
        Yaml {
            value: Default::default(),
        }
    }
}

fn from_slice(data: &[u8]) -> Results<Value> {
    match serde_yaml::from_slice(data) {
        Ok(dr) => Ok(dr),
        Err(err) => Err(Errs::strs("yaml from slice", err)),
    }
}

fn from_string(data: &str) -> Results<Value> {
    match serde_yaml::from_str(data) {
        Ok(dr) => Ok(dr),
        Err(err) => Err(Errs::strs("yaml from string", err)),
    }
}

#[cfg(test)]
mod yaml_test {
    use serde::{Deserialize, Serialize};
    use serde_yaml::Value;

    use crate::yaml::{YamlExec, YamlGet, YamlHandler, YamlNew};
    use crate::yaml::{Yaml, YamlArray};

    #[derive(Debug, Serialize, Deserialize)]
    struct User {
        name: String,
        age: u8,
        blog: String,
        addr: String,
    }

    const DATA: &str = r#"
                            name: John Doe
                            age: 43
                            phones:
                                - +44 1234567
                                - +44 2345678
                        "#;
    const USER: &str = r#"
                            name: 琼台博客
                            age: 30
                            blog: "https://www.qttc.net"
                            addr: 4114 Sepulveda Blvd
                        "#;
    const GET: &str = r#"
                            string: text
                            u64: 127
                            i64: -128
                            f64: 549.127
                            bool: false
                            object:
                              string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                        "#;
    const ARRAY: &str = r#"
                            string: text
                            u64: 127
                            i64: -128
                            f64: 549.127
                            bool: false
                            object:
                              string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                            array1:
                                - string: text
                                  u64: 127
                                  i64: -128
                                  f64: 549.127
                                  bool: false
                                  array:
                                    - hello
                                    - world
                                    - test
                                - string: text
                                  u64: 127
                                  i64: -128
                                  f64: 549.127
                                  bool: false
                                  array:
                                    - 1
                                    - 100
                                    - 10000
                                - string: text
                                  u64: 127
                                  i64: -128
                                  f64: 549.127
                                  bool: false
                                  array:
                                    - 5.4
                                    - 100.1
                                    - 10000.98
                            array2:
                                - one
                                - two
                                - three: object
                        "#;
    const ARRAYS: &str = r#"
                            - string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                              array:
                                - hello
                                - world
                                - test
                            - string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                              array:
                                - 1
                                - 100
                                - 10000
                            - string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                              array:
                                - 5.4
                                - 100.1
                                - 10000.98
                            - string: text
                              u64: 127
                              i64: -128
                              f64: 549.127
                              bool: false
                              array:
                                - 5.4
                                - test
                                - 10000
                                - false
                                - -99
                          "#;
    const ARRAY_OBJECT: &str = r#"
                                - name: 琼台博客
                                  age: 30
                                  blog: "https://www.qttc.net"
                                  addr: 4114 Sepulveda Blvd
                                - name: 琼台博客
                                  age: 30
                                  blog: "https://www.qttc.net"
                                  addr: 4114 Sepulveda Blvd
                               "#;
    const OBJECT: &str = r#"
                            version: '3.4'

                            services:

                              zookeeper1:
                                image: hyperledger/fabric-zookeeper:0.4.10
                                ports:
                                  - "2181:2181"
                                  - "2881:2888"
                                  - "3881:3888"
                                environment:
                                  - ZOO_MY_ID=1
                                  - ZOO_SERVERS=server.1=0.0.0.0:2881:3881 server.2=fabric_zookeeper2:2882:3882 server.3=fabric_zookeeper3:2883:3883
                                volumes:
                                    - /mount/fabric/test/back/zk1:/data
                                networks:
                                  - test
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              zookeeper2:
                                image: hyperledger/fabric-zookeeper:0.4.10
                                ports:
                                  - "2182:2181"
                                  - "2882:2888"
                                  - "3882:3888"
                                environment:
                                  - ZOO_MY_ID=2
                                  - ZOO_SERVERS=server.1=fabric_zookeeper1:2881:3881 server.2=0.0.0.0:2882:3882 server.3=fabric_zookeeper3:2883:3883
                                volumes:
                                    - /mount/fabric/test/back/zk2:/data
                                networks:
                                  - test
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              zookeeper3:
                                image: hyperledger/fabric-zookeeper:0.4.10
                                ports:
                                  - "2183:2181"
                                  - "2883:2888"
                                  - "3883:3888"
                                environment:
                                  - ZOO_MY_ID=3
                                  - ZOO_SERVERS=server.1=fabric_zookeeper1:2881:3881 server.2=fabric_zookeeper2:2882:3882 server.3=0.0.0.0:2883:3883
                                volumes:
                                    - /mount/fabric/test/back/zk3:/data
                                networks:
                                  - test
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              kafka1:
                                image: hyperledger/fabric-kafka:0.4.10
                                ports:
                                  - "9091:9092"
                                environment:
                                  - KAFKA_BROKER_ID=1
                                  - KAFKA_MIN_INSYNC_REPLICAS=2
                                  - KAFKA_DEFAULT_REPLICATION_FACTOR=3
                                  - KAFKA_ZOOKEEPER_CONNECT=fabric_zookeeper1:2181,fabric_zookeeper2:2182,fabric_zookeeper3:2183
                                  - KAFKA_MESSAGE_MAX_BYTES=103809024
                                  - KAFKA_REPLICA_FETCH_MAX_BYTES=103809024
                                  - KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false
                                  - KAFKA_LOG_RETENTION_MS=-1
                                  - KAFKA_HEAP_OPTS=-Xmx256M -Xms128M
                                networks:
                                  - test
                                depends_on:
                                  - fabric_zookeeper1
                                  - fabric_zookeeper2
                                  - fabric_zookeeper3
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              kafka2:
                                image: hyperledger/fabric-kafka:0.4.10
                                ports:
                                  - "9092:9092"
                                environment:
                                  - KAFKA_BROKER_ID=2
                                  - KAFKA_MIN_INSYNC_REPLICAS=2
                                  - KAFKA_DEFAULT_REPLICATION_FACTOR=3
                                  - KAFKA_ZOOKEEPER_CONNECT=fabric_zookeeper1:2181,fabric_zookeeper2:2182,fabric_zookeeper3:2183
                                  - KAFKA_MESSAGE_MAX_BYTES=103809024
                                  - KAFKA_REPLICA_FETCH_MAX_BYTES=103809024
                                  - KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false
                                  - KAFKA_LOG_RETENTION_MS=-1
                                  - KAFKA_HEAP_OPTS=-Xmx256M -Xms128M
                                networks:
                                  - test
                                depends_on:
                                  - fabric_zookeeper1
                                  - fabric_zookeeper2
                                  - fabric_zookeeper3
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              kafka3:
                                image: hyperledger/fabric-kafka:0.4.10
                                ports:
                                  - "9093:9092"
                                environment:
                                  - KAFKA_BROKER_ID=3
                                  - KAFKA_MIN_INSYNC_REPLICAS=2
                                  - KAFKA_DEFAULT_REPLICATION_FACTOR=3
                                  - KAFKA_ZOOKEEPER_CONNECT=fabric_zookeeper1:2181,fabric_zookeeper2:2182,fabric_zookeeper3:2183
                                  - KAFKA_MESSAGE_MAX_BYTES=103809024
                                  - KAFKA_REPLICA_FETCH_MAX_BYTES=103809024
                                  - KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false
                                  - KAFKA_LOG_RETENTION_MS=-1
                                  - KAFKA_HEAP_OPTS=-Xmx256M -Xms128M
                                networks:
                                  - test
                                depends_on:
                                  - fabric_zookeeper1
                                  - fabric_zookeeper2
                                  - fabric_zookeeper3
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                              kafka4:
                                image: hyperledger/fabric-kafka:0.4.10
                                ports:
                                  - "9094:9092"
                                environment:
                                  - KAFKA_BROKER_ID=4
                                  - KAFKA_MIN_INSYNC_REPLICAS=2
                                  - KAFKA_DEFAULT_REPLICATION_FACTOR=3
                                  - KAFKA_ZOOKEEPER_CONNECT=fabric_zookeeper1:2181,fabric_zookeeper2:2182,fabric_zookeeper3:2183
                                  - KAFKA_MESSAGE_MAX_BYTES=103809024
                                  - KAFKA_REPLICA_FETCH_MAX_BYTES=103809024
                                  - KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false
                                  - KAFKA_LOG_RETENTION_MS=-1
                                  - KAFKA_HEAP_OPTS=-Xmx256M -Xms128M
                                networks:
                                  - test
                                depends_on:
                                  - fabric_zookeeper1
                                  - fabric_zookeeper2
                                  - fabric_zookeeper3
                                deploy:
                                  mode: replicated
                                  replicas: 1
                                  restart_policy:
                                    condition: on-failure
                                    delay: 5s
                                    max_attempts: 3
                                  update_config:
                                    parallelism: 1
                                    delay: 10s

                            networks:
                              test:
                                driver: overlay
                         "#;

    #[test]
    fn test_self() {
        let yaml1 = Yaml::new(DATA).unwrap();
        let yaml2 = Yaml::new(DATA.to_string()).unwrap();
        let yaml3 = Yaml::new(DATA.as_bytes()).unwrap();
        let yaml4 = Yaml::new(DATA.as_bytes().to_vec()).unwrap();
        println!("yaml1 to string = {}", yaml1.to_string());
        println!("yaml2 to string = {}", yaml2.to_string());
        println!("yaml3 to string = {}", yaml3.to_string());
        println!("yaml4 to string = {}", yaml4.to_string());
        println!("yaml1 to slice = {:#?}", String::from_utf8(yaml1.to_vec()))
    }

    #[test]
    fn test_obj1() {
        let yaml = Yaml::new(USER).unwrap();
        println!("yaml = {:#?}", yaml.to_string());
        let user: User = yaml.to_object().unwrap();
        println!("user = {:#?}", user);
        let u1: User = Yaml::string_2_obj(yaml.to_string().as_str()).unwrap();
        println!("user = {:#?}", u1);
        let u2: User = Yaml::bytes_2_obj(yaml.to_vec().as_slice()).unwrap();
        println!("user = {:#?}", u2);
        let u3: User = Yaml::value_2_obj(yaml.value()).unwrap();
        println!("user = {:#?}", u3);
    }

    #[test]
    fn test_obj2() {
        let yaml = Yaml::new(OBJECT).unwrap();
        println!("yaml = {:#?}", yaml.to_string());
    }

    #[test]
    fn test_object_exec() {
        let yaml = Yaml::new(GET).unwrap();
        println!("string = {}", yaml.get_string("string").unwrap());
        println!("u64 = {}", yaml.get_u64("u64").unwrap());
        println!("i64 = {}", yaml.get_i64("i64").unwrap());
        println!("f64 = {}", yaml.get_f64("f64").unwrap());
        println!("bool = {}", yaml.get_bool("bool").unwrap());
        println!();
        println!("string = {}", yaml.is_string("string"));
        println!("u64 = {}", yaml.is_u64("u64"));
        println!("i64 = {}", yaml.is_i64("i64"));
        println!("f64 = {}", yaml.is_f64("f64"));
        println!("bool = {}", yaml.is_bool("bool"));
        println!();
        println!("string = {}", yaml.is_u64("string"));
        println!("u64 = {}", yaml.is_i64("u64"));
        println!("i64 = {}", yaml.is_f64("i64"));
        println!("f64 = {}", yaml.is_bool("f64"));
        println!("bool = {}", yaml.is_string("bool"));
        println!();
        let object = yaml.get_object("object").unwrap();
        println!("object string = {}", object.get_string("string").unwrap());
        println!("object u64 = {}", object.get_u64("u64").unwrap());
        println!("object i64 = {}", object.get_i64("i64").unwrap());
        println!("object f64 = {}", object.get_f64("f64").unwrap());
        println!("object bool = {}", object.get_bool("bool").unwrap());
    }

    #[test]
    fn test_array_self() {
        let array1 = Yaml::new(ARRAYS).unwrap();
        let array2 = Yaml::new(ARRAYS.to_string()).unwrap();
        let array3 = Yaml::new(ARRAYS.as_bytes()).unwrap();
        let array4 = Yaml::new(ARRAYS.as_bytes().to_vec()).unwrap();
        println!("array1 to string = {}", array1.to_string());
        println!("array2 to string = {}", array2.to_string());
        println!("array3 to string = {}", array3.to_string());
        println!("array4 to string = {}", array4.to_string());
        println!(
            "array1 to slice1 = {:#?}",
            String::from_utf8(array1.to_vec())
        );
        let value:Value = serde_yaml::from_slice(array1.to_vec().as_slice()).unwrap();
        let array1_1 = Yaml::new(value).unwrap();
        println!("array1_1 to string = {}", array1_1.to_string());
    }

    #[test]
    fn test_array_obj() {
        let array = YamlArray::new(ARRAY_OBJECT).unwrap();
        let users: Vec<User> = array.to_object().unwrap();
        println!("user = {:#?}", users);
    }

    #[test]
    fn test_array1() {
        let yaml = Yaml::new(ARRAY).unwrap();
        println!("string = {}", yaml.get_string("string").unwrap());
        println!("u64 = {}", yaml.get_u64("u64").unwrap());
        println!("i64 = {}", yaml.get_i64("i64").unwrap());
        println!("f64 = {}", yaml.get_f64("f64").unwrap());
        println!("bool = {}", yaml.get_bool("bool").unwrap());
        let array = yaml.get_array("array1").unwrap();
        let object = array.get_object(0).unwrap();
        println!("object string = {}", object.get_string("string").unwrap());
        println!("object u64 = {}", object.get_u64("u64").unwrap());
        println!("object i64 = {}", object.get_i64("i64").unwrap());
        println!("object f64 = {}", object.get_f64("f64").unwrap());
        println!("object bool = {}", object.get_bool("bool").unwrap());
        let array = object.get_array("array").unwrap();
        println!("array 0 = {}", array.get_string(0).unwrap());
    }

    #[test]
    fn test_array2() {
        let array = YamlArray::new(ARRAYS).unwrap();
        let yaml = array.get_object(0).unwrap();
        println!("string = {}", yaml.get_string("string").unwrap());
        println!("u64 = {}", yaml.get_u64("u64").unwrap());
        println!("i64 = {}", yaml.get_i64("i64").unwrap());
        println!("f64 = {}", yaml.get_f64("f64").unwrap());
        println!("bool = {}", yaml.get_bool("bool").unwrap());
        let array = yaml.get_array("array").unwrap();
        println!("array 0 = {}", array.get_string(0).unwrap());
    }

    #[test]
    fn test_array3() {
        let array = YamlArray::new(ARRAYS).unwrap();
        let yaml = array.get_object(3).unwrap();
        println!("string = {}", yaml.get_string("string").unwrap());
        println!("u64 = {}", yaml.get_u64("u64").unwrap());
        println!("i64 = {}", yaml.get_i64("i64").unwrap());
        println!("f64 = {}", yaml.get_f64("f64").unwrap());
        println!("bool = {}", yaml.get_bool("bool").unwrap());
        let array = yaml.get_array("array").unwrap();
        println!("array 0 = {}", array.get_f64(0).unwrap());
        println!("array 0 = {}", array.get_string(1).unwrap());
        println!("array 0 = {}", array.get_u64(2).unwrap());
        println!("array 0 = {}", array.get_bool(3).unwrap());
        println!("array 0 = {}", array.get_i64(4).unwrap());
    }

    #[test]
    fn test_out() {
        let user = User {
            name: "1".to_string(),
            age: 2,
            blog: "3".to_string(),
            addr: "4".to_string(),
        };
        println!("object to string = {}", Yaml::obj_2_string(&user).unwrap());
        println!(
            "object to string = {:#?}",
            String::from_utf8(Yaml::obj_2_bytes(&user).unwrap())
        );
        println!("object = {}", Yaml::object(&user).unwrap().to_string());
    }
}

