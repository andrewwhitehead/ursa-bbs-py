use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use pyo3::PyClass;

use bbs::prelude::{GroupElement, SignatureNonce};

use super::buffer::map_buffer_arg;
use super::error::PyBbsResult;

pub fn serialize_json_to_bytes<'py, T>(py: Python<'py>, obj: &T) -> PyResult<&'py PyBytes>
where
    T: serde::ser::Serialize,
{
    let result = serde_json::to_vec(obj).map_py_err()?;
    Ok(PyBytes::new(py, &result))
}

pub fn deserialize_json_arg<'py, T>(py: Python<'py>, arg: &PyAny) -> PyResult<T>
where
    T: for<'a> serde::Deserialize<'a>,
{
    if let Ok(strval) = <PyString as PyTryFrom>::try_from(arg) {
        serde_json::from_str::<T>(strval.to_string()?.as_ref()).map_py_err()
    } else {
        map_buffer_arg(py, arg, |bytes| {
            serde_json::from_slice::<T>(bytes).map_py_err()
        })
    }
}

pub fn serialize_field_element(val: SignatureNonce) -> PyResult<String> {
    Ok(val.to_hex())
}

pub fn deserialize_field_element<'py>(py: Python<'py>, arg: &PyAny) -> PyResult<SignatureNonce> {
    let strval = if let Ok(strval) = <PyString as PyTryFrom>::try_from(arg) {
        strval.to_string()?.to_string()
    } else {
        map_buffer_arg(py, arg, |bytes| {
            Ok(String::from_utf8_lossy(bytes).to_string())
        })?
    };
    SignatureNonce::from_hex(strval)
        .map_err(|e| ValueError::py_err(format!("Invalid JSON input: {}", e.to_string())))
}

pub fn serialize_group_element<T: GroupElement>(val: T) -> PyResult<String> {
    Ok(val.to_hex())
}

pub fn deserialize_group_element<'py, T: GroupElement>(
    py: Python<'py>,
    arg: &PyAny,
) -> PyResult<T> {
    let strval = if let Ok(strval) = <PyString as PyTryFrom>::try_from(arg) {
        strval.to_string()?.to_string()
    } else {
        map_buffer_arg(py, arg, |bytes| {
            Ok(String::from_utf8_lossy(bytes).to_string())
        })?
    };
    T::from_hex(strval)
        .map_err(|e| ValueError::py_err(format!("Invalid JSON input: {}", e.to_string())))
}

pub trait ParseArg: PyClass {
    type Target: Sized;
    fn parse_arg<'py>(py: Python<'py>, arg: &'py PyAny) -> PyResult<ExtractArg<'py, Self>>;
    fn to_ref<'py>(arg: &'py PyRef<Self>) -> &'py Self::Target;
    fn to_owned(arg: PyRef<Self>) -> Self::Target;
}

pub enum ExtractArg<'a, T: ParseArg> {
    Ref(PyRef<'a, T>),
    Owned(T::Target),
}

impl<'a, T: ParseArg> ExtractArg<'a, T> {
    pub fn into_owned(self) -> T::Target {
        match self {
            Self::Ref(a) => T::to_owned(a),
            Self::Owned(b) => b,
        }
    }
}

impl<'a, T: ParseArg> std::ops::Deref for ExtractArg<'a, T> {
    type Target = T::Target;
    fn deref(&self) -> &T::Target {
        match self {
            Self::Ref(a) => T::to_ref(a),
            Self::Owned(ref b) => b,
        }
    }
}

impl<'a, T: ParseArg> FromPyObject<'a> for ExtractArg<'a, T> {
    fn extract(input: &'a PyAny) -> PyResult<ExtractArg<'a, T>> {
        let py = unsafe { Python::assume_gil_acquired() };
        T::parse_arg(py, input)
    }
}
