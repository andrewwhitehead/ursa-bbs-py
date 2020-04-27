use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use pyo3::PyClass;

use bbs::prelude::{CompressedBytes, SignatureNonce};

use super::buffer::map_buffer_arg;
use super::error::PyBbsResult;
use std::convert::TryFrom;

pub fn py_bytes<'py, T>(py: Python<'py>, obj: T) -> &'py PyBytes
where
    T: AsRef<[u8]>,
{
    PyBytes::new(py, obj.as_ref())
}

pub fn serialize_compressed<T>(obj: &T) -> PyResult<Vec<u8>>
where
    T: CompressedBytes,
{
    Ok(obj.to_compressed_bytes())
}

pub fn py_serialize_compressed<'py, T>(py: Python<'py>, obj: &T) -> PyResult<&'py PyBytes>
where
    T: CompressedBytes,
{
    Ok(py_bytes(py, serialize_compressed(obj)?))
}

pub fn py_deserialize_compressed<'py, T>(py: Python<'py>, arg: &PyAny) -> PyResult<T>
where
    T: CompressedBytes<Output = T>,
    Result<T::Output, T::Error>: PyBbsResult<T::Output>,
{
    map_buffer_arg(py, arg, |bytes| {
        T::from_compressed_bytes(bytes).map_py_err()
    })
}

pub fn py_serialize_json<'py, T>(py: Python<'py>, obj: &T) -> PyResult<&'py PyBytes>
where
    T: serde::ser::Serialize,
{
    let result = serde_json::to_vec(obj).map_py_err()?;
    Ok(py_bytes(py, result))
}

pub fn py_deserialize_json<'py, T>(py: Python<'py>, arg: &PyAny) -> PyResult<T>
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

pub fn serialize_field_element(val: SignatureNonce) -> PyResult<Vec<u8>> {
    Ok(val.to_compressed_bytes().to_vec())
}

pub fn deserialize_field_element<'py>(py: Python<'py>, arg: &PyAny) -> PyResult<SignatureNonce> {
    map_buffer_arg(py, arg, |bytes| {
        SignatureNonce::try_from(bytes)
            .map_err(|e| ValueError::py_err(format!("Invalid field element: {}", e.to_string())))
    })
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
