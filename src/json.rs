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
use serde_json::Value;

use crate::errors::{Errs, Results};

pub struct Json {
    value: serde_json::Value,
}

pub struct JsonArray {
    value: serde_json::Value,
}

pub trait JsonHandler {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
            Self: std::marker::Sized;

    fn value(&self) -> Value;

    fn to_string(&self) -> String {
        self.value().to_string()
    }

    fn to_vec(&self) -> Vec<u8> {
        self.value().to_string().into_bytes()
    }

    fn to_object<Object>(&self) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_json::from_value(self.value()) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("json to object", err)),
        }
    }

    fn obj_2_bytes<Object>(value: &Object) -> Results<Vec<u8>>
        where
            Object: ?Sized + Serialize,
    {
        match serde_json::to_vec(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn obj_2_string<Object>(value: &Object) -> Results<String>
        where
            Object: ?Sized + Serialize,
    {
        match serde_json::to_string(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to string", err)),
        }
    }

    fn obj_2_value<Object>(value: &Object) -> Results<Value>
        where
            Object: ?Sized + Serialize,
    {
        match serde_json::to_value(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Errs::strs("object to string", err)),
        }
    }

    fn bytes_2_obj<Object>(data: &[u8]) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_json::from_slice(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("json to object", err)),
        }
    }

    fn string_2_obj<Object>(data: &str) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_json::from_str(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("json to object", err)),
        }
    }

    fn value_2_obj<Object>(data: Value) -> Results<Object>
        where
            Object: DeserializeOwned,
    {
        match serde_json::from_value(data) {
            Ok(t) => Ok(t),
            Err(err) => Err(Errs::strs("json to object", err)),
        }
    }
}

pub trait JsonNew<T>: Sized {
    fn new(data: T) -> Results<Self>;
    fn from(&mut self, data: T) -> Results<()>;
}

pub trait JsonExec<Param> {
    /// 表示json中不存在`param`或者`param`的值为null
    fn has(&self, param: Param) -> bool;
    fn take_string(&mut self, param: Param) -> Results<String>;
    fn take_u64(&mut self, param: Param) -> Results<u64>;
    fn take_i64(&mut self, param: Param) -> Results<i64>;
    fn take_f64(&mut self, param: Param) -> Results<f64>;
    fn take_bool(&mut self, param: Param) -> Results<bool>;
    fn take_object(&mut self, param: Param) -> Results<Json>;
    fn take_array(&mut self, param: Param) -> Results<JsonArray>;
    fn is_string(&self, param: Param) -> bool;
    fn is_u64(&self, param: Param) -> bool;
    fn is_i64(&self, param: Param) -> bool;
    fn is_f64(&self, param: Param) -> bool;
    fn is_bool(&self, param: Param) -> bool;
    fn is_object(&self, param: Param) -> bool;
    fn is_array(&self, param: Param) -> bool;
}

pub trait JsonGet<Param> {
    fn get_value(&self, param: Param) -> Results<Value>;
    fn get_string(&self, param: Param) -> Results<String>;
    fn get_u64(&self, param: Param) -> Results<u64>;
    fn get_i64(&self, param: Param) -> Results<i64>;
    fn get_f64(&self, param: Param) -> Results<f64>;
    fn get_bool(&self, param: Param) -> Results<bool>;
    fn get_object(&self, param: Param) -> Results<Json>;
    fn get_array(&self, param: Param) -> Results<JsonArray>;
}

impl JsonHandler for Json {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
    {
        match serde_json::to_value(object) {
            Ok(res) => Ok(Json { value: res }),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn value(&self) -> Value {
        self.value.clone()
    }
}

impl JsonNew<&[u8]> for Json {
    fn new(data: &[u8]) -> Results<Self> {
        Ok(Json {
            value: from_slice(data)?,
        })
    }

    fn from(&mut self, data: &[u8]) -> Results<()> {
        self.value = from_slice(data)?;
        Ok(())
    }
}

impl JsonNew<Vec<u8>> for Json {
    fn new(data: Vec<u8>) -> Results<Self> {
        Ok(Json {
            value: from_slice(data.as_slice())?,
        })
    }

    fn from(&mut self, data: Vec<u8>) -> Results<()> {
        self.value = from_slice(data.as_slice())?;
        Ok(())
    }
}

impl JsonNew<&str> for Json {
    fn new(data: &str) -> Results<Self> {
        Ok(Json {
            value: from_string(data)?,
        })
    }

    fn from(&mut self, data: &str) -> Results<()> {
        self.value = from_string(data)?;
        Ok(())
    }
}

impl JsonNew<String> for Json {
    fn new(data: String) -> Results<Self> {
        Ok(Json {
            value: from_string(data.as_str())?,
        })
    }

    fn from(&mut self, data: String) -> Results<()> {
        self.value = from_string(data.as_str())?;
        Ok(())
    }
}

impl JsonNew<Value> for Json {
    fn new(value: Value) -> Results<Self> {
        Ok(Json { value })
    }

    fn from(&mut self, value: Value) -> Results<()> {
        self.value.clone_from(&value);
        Ok(())
    }
}

impl JsonNew<&Value> for Json {
    fn new(value: &Value) -> Results<Self> {
        Ok(Json {
            value: value.clone(),
        })
    }

    fn from(&mut self, value: &Value) -> Results<()> {
        self.value.clone_from(value);
        Ok(())
    }
}

impl JsonExec<&str> for Json {
    fn has(&self, param: &str) -> bool {
        self.value[param] == Value::Null
    }

    fn take_string(&mut self, param: &str) -> Results<String> {
        match self.value[param].take().as_str() {
            Some(res) => Ok(res.to_string()),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans string!",
                param
            ))),
        }
    }

    fn take_u64(&mut self, param: &str) -> Results<u64> {
        match self.value[param].take().as_u64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans u64!",
                param
            ))),
        }
    }

    fn take_i64(&mut self, param: &str) -> Results<i64> {
        match self.value[param].take().as_i64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans i64!",
                param
            ))),
        }
    }

    fn take_f64(&mut self, param: &str) -> Results<f64> {
        match self.value[param].take().as_f64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans f64!",
                param
            ))),
        }
    }

    fn take_bool(&mut self, param: &str) -> Results<bool> {
        match self.value[param].take().as_bool() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans bool!",
                param
            ))),
        }
    }

    fn take_object(&mut self, param: &str) -> Results<Json> {
        Json::new(self.value[param].take())
    }

    fn take_array(&mut self, param: &str) -> Results<JsonArray> {
        JsonArray::new(self.value[param].take())
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
        self.value[param].is_boolean()
    }

    fn is_object(&self, param: &str) -> bool {
        self.value[param].is_object()
    }

    fn is_array(&self, param: &str) -> bool {
        self.value[param].is_array()
    }
}

impl JsonExec<String> for Json {
    fn has(&self, param: String) -> bool {
        self.value[param] != Value::Null
    }

    fn take_string(&mut self, param: String) -> Results<String> {
        match self.value[param.clone()].take().as_str() {
            Some(res) => Ok(res.to_string()),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans string!",
                param
            ))),
        }
    }

    fn take_u64(&mut self, param: String) -> Results<u64> {
        match self.value[param.clone()].take().as_u64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans u64!",
                param
            ))),
        }
    }

    fn take_i64(&mut self, param: String) -> Results<i64> {
        match self.value[param.clone()].take().as_i64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans i64!",
                param
            ))),
        }
    }

    fn take_f64(&mut self, param: String) -> Results<f64> {
        match self.value[param.clone()].take().as_f64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans f64!",
                param
            ))),
        }
    }

    fn take_bool(&mut self, param: String) -> Results<bool> {
        match self.value[param.clone()].take().as_bool() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans bool!",
                param
            ))),
        }
    }

    fn take_object(&mut self, param: String) -> Results<Json> {
        Json::new(self.value[param.clone()].take())
    }

    fn take_array(&mut self, param: String) -> Results<JsonArray> {
        JsonArray::new(self.value[param.clone()].take())
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
        self.value[param].is_boolean()
    }

    fn is_object(&self, param: String) -> bool {
        self.value[param].is_object()
    }

    fn is_array(&self, param: String) -> bool {
        self.value[param].is_array()
    }
}

impl JsonGet<&str> for Json {
    fn get_value(&self, param: &str) -> Results<Value> {
        Ok(self.value[param].clone())
    }

    fn get_string(&self, param: &str) -> Results<String> {
        match self.value[param].as_str() {
            Some(res) => Ok(res.to_string()),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans string!",
                param
            ))),
        }
    }

    fn get_u64(&self, param: &str) -> Results<u64> {
        match self.value[param].as_u64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans u64!",
                param
            ))),
        }
    }

    fn get_i64(&self, param: &str) -> Results<i64> {
        match self.value[param].as_i64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans i64!",
                param
            ))),
        }
    }

    fn get_f64(&self, param: &str) -> Results<f64> {
        match self.value[param].as_f64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans f64!",
                param
            ))),
        }
    }

    fn get_bool(&self, param: &str) -> Results<bool> {
        match self.value[param].as_bool() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans bool!",
                param
            ))),
        }
    }

    fn get_object(&self, param: &str) -> Results<Json> {
        match self.value.get(param) {
            Some(res) => Json::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans object!",
                param
            ))),
        }
    }

    fn get_array(&self, param: &str) -> Results<JsonArray> {
        match self.value.get(param) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans array!",
                param
            ))),
        }
    }
}

impl JsonGet<String> for Json {
    fn get_value(&self, param: String) -> Results<Value> {
        Ok(self.value[param].clone())
    }

    fn get_string(&self, param: String) -> Results<String> {
        match self.value[param.clone()].as_str() {
            Some(res) => Ok(res.to_string()),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans string!",
                param
            ))),
        }
    }

    fn get_u64(&self, param: String) -> Results<u64> {
        match self.value[param.clone()].as_u64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans u64!",
                param
            ))),
        }
    }

    fn get_i64(&self, param: String) -> Results<i64> {
        match self.value[param.clone()].as_i64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans i64!",
                param
            ))),
        }
    }

    fn get_f64(&self, param: String) -> Results<f64> {
        match self.value[param.clone()].as_f64() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans f64!",
                param
            ))),
        }
    }

    fn get_bool(&self, param: String) -> Results<bool> {
        match self.value[param.clone()].as_bool() {
            Some(res) => Ok(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans bool!",
                param
            ))),
        }
    }

    fn get_object(&self, param: String) -> Results<Json> {
        match self.value.get(param.clone()) {
            Some(res) => Json::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans object!",
                param
            ))),
        }
    }

    fn get_array(&self, param: String) -> Results<JsonArray> {
        match self.value.get(param.clone()) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::string(format!(
                "param {} not found or can not trans array!",
                param
            ))),
        }
    }
}

impl JsonHandler for JsonArray {
    fn object<Object>(object: &Object) -> Results<Self>
        where
            Object: ?Sized + Serialize,
    {
        match serde_json::to_value(object) {
            Ok(res) => Ok(JsonArray { value: res }),
            Err(err) => Err(Errs::strs("object to bytes", err)),
        }
    }

    fn value(&self) -> Value {
        self.value.clone()
    }
}

impl JsonNew<&[u8]> for JsonArray {
    fn new(data: &[u8]) -> Results<Self> {
        Ok(JsonArray {
            value: from_slice(data)?,
        })
    }

    fn from(&mut self, data: &[u8]) -> Results<()> {
        self.value = from_slice(data)?;
        Ok(())
    }
}

impl JsonNew<Vec<u8>> for JsonArray {
    fn new(data: Vec<u8>) -> Results<Self> {
        Ok(JsonArray {
            value: from_slice(data.as_slice())?,
        })
    }

    fn from(&mut self, data: Vec<u8>) -> Results<()> {
        self.value = from_slice(data.as_slice())?;
        Ok(())
    }
}

impl JsonNew<&str> for JsonArray {
    fn new(data: &str) -> Results<Self> {
        Ok(JsonArray {
            value: from_string(data)?,
        })
    }

    fn from(&mut self, data: &str) -> Results<()> {
        self.value = from_string(data)?;
        Ok(())
    }
}

impl JsonNew<String> for JsonArray {
    fn new(data: String) -> Results<Self> {
        Ok(JsonArray {
            value: from_string(data.as_str())?,
        })
    }

    fn from(&mut self, data: String) -> Results<()> {
        self.value = from_string(data.as_str())?;
        Ok(())
    }
}

impl JsonNew<Value> for JsonArray {
    fn new(value: Value) -> Results<Self> {
        Ok(JsonArray { value })
    }

    fn from(&mut self, value: Value) -> Results<()> {
        self.value.clone_from(&value);
        Ok(())
    }
}

impl JsonNew<&Value> for JsonArray {
    fn new(value: &Value) -> Results<Self> {
        Ok(JsonArray {
            value: value.clone(),
        })
    }

    fn from(&mut self, value: &Value) -> Results<()> {
        self.value.clone_from(value);
        Ok(())
    }
}

impl JsonGet<usize> for JsonArray {
    fn get_value(&self, index: usize) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: usize) -> Results<String> {
        match self.value.get(index) {
            Some(res) => match res.as_str() {
                Some(res) => Ok(res.to_string()),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_u64(&self, index: usize) -> Results<u64> {
        match self.value.get(index) {
            Some(res) => match res.as_u64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get u64!")),
        }
    }

    fn get_i64(&self, index: usize) -> Results<i64> {
        match self.value.get(index) {
            Some(res) => match res.as_i64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get i64!")),
        }
    }

    fn get_f64(&self, index: usize) -> Results<f64> {
        match self.value.get(index) {
            Some(res) => match res.as_f64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get f64!")),
        }
    }

    fn get_bool(&self, index: usize) -> Results<bool> {
        match self.value.get(index) {
            Some(res) => match res.as_bool() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }

    fn get_object(&self, index: usize) -> Results<Json> {
        match self.value.get(index) {
            Some(res) => Json::new(res),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }

    fn get_array(&self, index: usize) -> Results<JsonArray> {
        match self.value.get(index) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }
}

impl JsonGet<i32> for JsonArray {
    fn get_value(&self, index: i32) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: i32) -> Results<String> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_str() {
                Some(res) => Ok(res.to_string()),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_u64(&self, index: i32) -> Results<u64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_u64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get u64!")),
        }
    }

    fn get_i64(&self, index: i32) -> Results<i64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_i64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get i64!")),
        }
    }

    fn get_f64(&self, index: i32) -> Results<f64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_f64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get f64!")),
        }
    }

    fn get_bool(&self, index: i32) -> Results<bool> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_bool() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }

    fn get_object(&self, index: i32) -> Results<Json> {
        match self.value.get(index as usize) {
            Some(res) => Json::new(res),
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_array(&self, index: i32) -> Results<JsonArray> {
        match self.value.get(index as usize) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }
}

impl JsonGet<u32> for JsonArray {
    fn get_value(&self, index: u32) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: u32) -> Results<String> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_str() {
                Some(res) => Ok(res.to_string()),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_u64(&self, index: u32) -> Results<u64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_u64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get u64!")),
        }
    }

    fn get_i64(&self, index: u32) -> Results<i64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_i64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get i64!")),
        }
    }

    fn get_f64(&self, index: u32) -> Results<f64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_f64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get f64!")),
        }
    }

    fn get_bool(&self, index: u32) -> Results<bool> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_bool() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }

    fn get_object(&self, index: u32) -> Results<Json> {
        match self.value.get(index as usize) {
            Some(res) => Json::new(res),
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_array(&self, index: u32) -> Results<JsonArray> {
        match self.value.get(index as usize) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }
}

impl JsonGet<u64> for JsonArray {
    fn get_value(&self, index: u64) -> Results<Value> {
        match self.value.get(index as usize) {
            Some(res) => Ok(res.clone()),
            None => Err(Errs::string(format!(
                "value can not get from json array while index is {}!",
                index
            ))),
        }
    }

    fn get_string(&self, index: u64) -> Results<String> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_str() {
                Some(res) => Ok(res.to_string()),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get string!")),
        }
    }

    fn get_u64(&self, index: u64) -> Results<u64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_u64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get u64!")),
        }
    }

    fn get_i64(&self, index: u64) -> Results<i64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_i64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get i64!")),
        }
    }

    fn get_f64(&self, index: u64) -> Results<f64> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_f64() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get f64!")),
        }
    }

    fn get_bool(&self, index: u64) -> Results<bool> {
        match self.value.get(index as usize) {
            Some(res) => match res.as_bool() {
                Some(res) => Ok(res),
                None => Err(Errs::string(format!(
                    "value can not get from json array while index is {}!",
                    index
                ))),
            },
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }

    fn get_object(&self, index: u64) -> Results<Json> {
        match self.value.get(index as usize) {
            Some(res) => Json::new(res),
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }

    fn get_array(&self, index: u64) -> Results<JsonArray> {
        match self.value.get(index as usize) {
            Some(res) => JsonArray::new(res),
            None => Err(Errs::str("index out of bound while json array get bool!")),
        }
    }
}

impl Default for Json {
    fn default() -> Json {
        Json {
            value: Default::default(),
        }
    }
}

impl Default for JsonArray {
    fn default() -> JsonArray {
        JsonArray {
            value: Default::default(),
        }
    }
}

fn from_slice(data: &[u8]) -> Results<Value> {
    // let map:Map<String, Value> = serde_json::from_slice(data).unwrap();
    match serde_json::from_slice(data) {
        Ok(dr) => Ok(dr),
        Err(err) => Err(Errs::strs("json from slice", err)),
    }
}

fn from_string(data: &str) -> Results<Value> {
    match serde_json::from_str(data) {
        Ok(dr) => Ok(dr),
        Err(err) => Err(Errs::strs("json from string", err)),
    }
}

#[cfg(test)]
mod json_test {
    use serde::{Deserialize, Serialize};

    use crate::json::{Json, JsonArray};
    use crate::json::{JsonExec, JsonGet, JsonHandler, JsonNew};

    #[derive(Debug, Serialize, Deserialize)]
    struct User {
        name: String,
        age: u8,
        blog: String,
        addr: String,
    }

    const DATA: &str = r#"
                        {
                            "name": "John Doe",
                            "age": 43,
                            "phones": [
                                "+44 1234567",
                                "+44 2345678"
                            ]
                        }"#;
    const USER: &str = r#"
                        {
                            "name": "琼台博客",
                            "age": 30,
                            "blog": "https://www.qttc.net",
                            "addr": "4114 Sepulveda Blvd"
                        }"#;
    const GET: &str = r#"
                        {
                            "string": "text",
                            "u64": 127,
                            "i64": -128,
                            "f64": 549.127,
                            "bool": false,
                            "object": {
                                          "string": "text",
                                          "u64": 127,
                                          "i64": -128,
                                          "f64": 549.127,
                                          "bool": false
                                       }
                        }"#;
    const ARRAY: &str = r#"
                        {
                            "string": "text",
                            "u64": 127,
                            "i64": -128,
                            "f64": 549.127,
                            "bool": false,
                            "object": {
                                          "string": "text",
                                          "u64": 127,
                                          "i64": -128,
                                          "f64": 549.127,
                                          "bool": false
                             },
                            "array1": [
                                {
                                    "string": "text",
                                    "u64": 127,
                                    "i64": -128,
                                    "f64": 549.127,
                                    "bool": false,
                                    "array": ["hello", "world", "test"]
                                },
                                {
                                    "string": "text",
                                    "u64": 127,
                                    "i64": -128,
                                    "f64": 549.127,
                                    "bool": false,
                                    "array": [1, 100, 10000]
                                },
                                {
                                    "string": "text",
                                    "u64": 127,
                                    "i64": -128,
                                    "f64": 549.127,
                                    "bool": false,
                                    "array": [5.4, 100.1, 10000.98]
                                }
                            ],
                            "array2": ["one", "two", { "three": "object" }]
                        }"#;
    const ARRAYS: &str = r#"
                        [
                            {
                                "string": "text",
                                "u64": 127,
                                "i64": -128,
                                "f64": 549.127,
                                "bool": false,
                                "array": ["hello", "world", "test"]
                            },
                            {
                                "string": "text",
                                "u64": 127,
                                "i64": -128,
                                "f64": 549.127,
                                "bool": false,
                                "array": [1, 100, 10000]
                            },
                            {
                                "string": "text",
                                "u64": 127,
                                "i64": -128,
                                "f64": 549.127,
                                "bool": false,
                                "array": [5.4, 100.1, 10000.98]
                            },
                            {
                                "string": "text",
                                "u64": 127,
                                "i64": -128,
                                "f64": 549.127,
                                "bool": false,
                                "array": [5.4, "test", 10000, false, -99]
                            }
                        ]
                        "#;
    const ARRAY_OBJECT: &str = r#"
                        [
                            {
                                "name": "琼台博客",
                                "age": 30,
                                "blog": "https://www.qttc.net",
                                "addr": "4114 Sepulveda Blvd"
                            },
                            {
                                "name": "琼台博客",
                                "age": 30,
                                "blog": "https://www.qttc.net",
                                "addr": "4114 Sepulveda Blvd"
                            }
                        ]
                        "#;

    #[test]
    fn test_self() {
        let json1 = Json::new(DATA).unwrap();
        let json2 = Json::new(DATA.to_string()).unwrap();
        let json3 = Json::new(DATA.as_bytes()).unwrap();
        let json4 = Json::new(DATA.as_bytes().to_vec()).unwrap();
        println!("json1 to string = {}", json1.to_string());
        println!("json2 to string = {}", json2.to_string());
        println!("json3 to string = {}", json3.to_string());
        println!("json4 to string = {}", json4.to_string());
        println!("json1 to slice = {:#?}", String::from_utf8(json1.to_vec()))
    }

    #[test]
    fn test_obj() {
        let json = Json::new(USER).unwrap();
        let user: User = json.to_object().unwrap();
        println!("user = {:#?}", user);
        let u1: User = Json::string_2_obj(json.to_string().as_str()).unwrap();
        println!("user = {:#?}", u1);
        let u2: User = Json::bytes_2_obj(json.to_vec().as_slice()).unwrap();
        println!("user = {:#?}", u2);
        let u3: User = Json::value_2_obj(json.value()).unwrap();
        println!("user = {:#?}", u3);
    }

    #[test]
    fn test_object_exec() {
        let json = Json::new(GET).unwrap();
        println!("string = {}", json.get_string("string").unwrap());
        println!("u64 = {}", json.get_u64("u64").unwrap());
        println!("i64 = {}", json.get_i64("i64").unwrap());
        println!("f64 = {}", json.get_f64("f64").unwrap());
        println!("bool = {}", json.get_bool("bool").unwrap());
        println!();
        println!("string = {}", json.is_string("string"));
        println!("u64 = {}", json.is_u64("u64"));
        println!("i64 = {}", json.is_i64("i64"));
        println!("f64 = {}", json.is_f64("f64"));
        println!("bool = {}", json.is_bool("bool"));
        println!();
        println!("string = {}", json.is_u64("string"));
        println!("u64 = {}", json.is_i64("u64"));
        println!("i64 = {}", json.is_f64("i64"));
        println!("f64 = {}", json.is_bool("f64"));
        println!("bool = {}", json.is_string("bool"));
        println!();
        let object = json.get_object("object").unwrap();
        println!("object string = {}", object.get_string("string").unwrap());
        println!("object u64 = {}", object.get_u64("u64").unwrap());
        println!("object i64 = {}", object.get_i64("i64").unwrap());
        println!("object f64 = {}", object.get_f64("f64").unwrap());
        println!("object bool = {}", object.get_bool("bool").unwrap());
    }

    #[test]
    fn test_array_self() {
        let array1 = Json::new(ARRAYS).unwrap();
        let array2 = Json::new(ARRAYS.to_string()).unwrap();
        let array3 = Json::new(ARRAYS.as_bytes()).unwrap();
        let array4 = Json::new(ARRAYS.as_bytes().to_vec()).unwrap();
        println!("array1 to string = {}", array1.to_string());
        println!("array2 to string = {}", array2.to_string());
        println!("array3 to string = {}", array3.to_string());
        println!("array4 to string = {}", array4.to_string());
        println!(
            "array1 to slice = {:#?}",
            String::from_utf8(array1.to_vec())
        )
    }

    #[test]
    fn test_array_obj() {
        let array = JsonArray::new(ARRAY_OBJECT).unwrap();
        let users: Vec<User> = array.to_object().unwrap();
        println!("user = {:#?}", users);
    }

    #[test]
    fn test_array1() {
        let json = Json::new(ARRAY).unwrap();
        println!("string = {}", json.get_string("string").unwrap());
        println!("u64 = {}", json.get_u64("u64").unwrap());
        println!("i64 = {}", json.get_i64("i64").unwrap());
        println!("f64 = {}", json.get_f64("f64").unwrap());
        println!("bool = {}", json.get_bool("bool").unwrap());
        let array = json.get_array("array1").unwrap();
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
        let array = JsonArray::new(ARRAYS).unwrap();
        let json = array.get_object(0).unwrap();
        println!("string = {}", json.get_string("string").unwrap());
        println!("u64 = {}", json.get_u64("u64").unwrap());
        println!("i64 = {}", json.get_i64("i64").unwrap());
        println!("f64 = {}", json.get_f64("f64").unwrap());
        println!("bool = {}", json.get_bool("bool").unwrap());
        let array = json.get_array("array").unwrap();
        println!("array 0 = {}", array.get_string(0).unwrap());
    }

    #[test]
    fn test_array3() {
        let array = JsonArray::new(ARRAYS).unwrap();
        let json = array.get_object(3).unwrap();
        println!("string = {}", json.get_string("string").unwrap());
        println!("u64 = {}", json.get_u64("u64").unwrap());
        println!("i64 = {}", json.get_i64("i64").unwrap());
        println!("f64 = {}", json.get_f64("f64").unwrap());
        println!("bool = {}", json.get_bool("bool").unwrap());
        let array = json.get_array("array").unwrap();
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
        println!("object to string = {}", Json::obj_2_string(&user).unwrap());
        println!(
            "object to string = {:#?}",
            String::from_utf8(Json::obj_2_bytes(&user).unwrap())
        );
        println!("object = {}", Json::object(&user).unwrap().to_string());
    }
}

