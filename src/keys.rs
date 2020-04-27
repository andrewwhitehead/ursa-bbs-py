use bbs::prelude::{
    DeterministicPublicKey, DomainSeparationTag, Issuer, KeyGenOption, PublicKey, SecretKey,
    SECRET_KEY_SIZE,
};

use pyo3::class::{PyBufferProtocol, PyObjectProtocol};
use pyo3::exceptions::ValueError;
use pyo3::ffi::Py_buffer;
use pyo3::prelude::*;
use pyo3::{wrap_pyfunction, PyRefMut, PyTypeInfo};

use std::os::raw::c_int;

use zeroize::Zeroize;

use super::buffer::{copy_buffer_arg, copy_buffer_opt_arg, create_safe_buffer, release_buffer};
use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, py_deserialize_json, py_serialize_json, ExtractArg, ParseArg,
};

#[pyclass(name=PublicKey)]
pub struct PyPublicKey {
    inner: PublicKey,
}

py_compressed_bytes_wrapper!(PyPublicKey, PublicKey);

#[pyclass(name=DeterministicPublicKey)]
pub struct PyDeterministicPublicKey {
    inner: DeterministicPublicKey,
}

#[pymethods]
impl PyDeterministicPublicKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        let inner = <Self as ParseArg>::parse_arg(py, data)?.into_owned();
        Ok(Self::new(inner))
    }

    /// Create a new public key given the message count and domain separation tag
    #[text_signature = "(message_count, dst)"]
    pub fn to_public_key(
        &self,
        message_count: usize,
        dst: ExtractArg<PyDomainSeparationTag>,
    ) -> PyResult<PyPublicKey> {
        let pk = (&self.inner)
            .to_public_key(message_count, dst.to_owned())
            .map_py_err()?;
        Ok(PyPublicKey::new(pk))
    }

    #[text_signature = "()"]
    pub fn to_json(slf: PyRef<Self>) -> PyResult<String> {
        py_serialize_json(&slf.inner)
    }
}

#[pyproto]
impl PyBufferProtocol for PyDeterministicPublicKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = serde_json::to_vec(&slf.inner).map_py_err()?;
        let py = unsafe { Python::assume_gil_acquired() };
        create_safe_buffer(py, buf, view, flags)
    }

    fn bf_releasebuffer(_slf: PyRefMut<Self>, view: *mut Py_buffer) -> PyResult<()> {
        release_buffer(view)
    }
}

#[pyproto]
impl PyObjectProtocol for PyDeterministicPublicKey {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("DeterministicPublicKey({:p})", self))
    }
}

impl PyDeterministicPublicKey {
    pub fn new(inner: DeterministicPublicKey) -> Self {
        Self { inner }
    }
}

impl std::ops::Deref for PyDeterministicPublicKey {
    type Target = DeterministicPublicKey;
    fn deref(&self) -> &DeterministicPublicKey {
        &self.inner
    }
}

impl ParseArg for PyDeterministicPublicKey {
    type Target = DeterministicPublicKey;
    fn parse_arg<'py>(py: Python<'py>, arg: &'py PyAny) -> PyResult<ExtractArg<'py, Self>> {
        if <PySecretKey as PyTypeInfo>::is_instance(arg) {
            let skref = <PyRef<PySecretKey> as FromPyObject>::extract(arg)?;
            let (dpk, _sk) =
                DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(skref.to_owned())));
            Ok(ExtractArg::Owned(dpk))
        } else if <Self as PyTypeInfo>::is_instance(arg) {
            let inst = <PyRef<Self> as FromPyObject<'py>>::extract(arg)?;
            Ok(ExtractArg::Ref(inst))
        } else {
            py_deserialize_json(py, arg).map(ExtractArg::Owned)
        }
    }
    fn to_ref<'py>(arg: &'py PyRef<Self>) -> &'py Self::Target {
        &arg.inner
    }
    fn to_owned(arg: PyRef<Self>) -> Self::Target {
        arg.inner.to_owned()
    }
}

#[pyclass(name=SecretKey)]
pub struct PySecretKey {
    inner: SecretKey,
}

#[pymethods]
impl PySecretKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        let inner = <Self as ParseArg>::parse_arg(py, data)?.into_owned();
        Ok(Self::new(inner))
    }
}

#[pyproto]
impl PyBufferProtocol for PySecretKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let mut buf = vec![0u8; SECRET_KEY_SIZE * 2];
        let mut hex = slf.inner.to_hex();
        buf.copy_from_slice(hex.as_bytes());
        hex.zeroize();
        let py = unsafe { Python::assume_gil_acquired() };
        create_safe_buffer(py, buf, view, flags)
    }

    fn bf_releasebuffer(_slf: PyRefMut<Self>, view: *mut Py_buffer) -> PyResult<()> {
        release_buffer(view)
    }
}

#[pyproto]
impl PyObjectProtocol for PySecretKey {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("SecretKey({:p})", self))
    }
}

impl PySecretKey {
    pub fn new(inner: SecretKey) -> Self {
        Self { inner }
    }

    pub fn to_owned(&self) -> SecretKey {
        self.inner.to_owned()
    }
}

impl std::ops::Deref for PySecretKey {
    type Target = SecretKey;
    fn deref(&self) -> &SecretKey {
        &self.inner
    }
}

impl ParseArg for PySecretKey {
    type Target = SecretKey;
    fn parse_arg<'py>(py: Python<'py>, arg: &'py PyAny) -> PyResult<ExtractArg<'py, Self>> {
        if <Self as PyTypeInfo>::is_instance(arg) {
            let inst = <PyRef<Self> as FromPyObject<'py>>::extract(arg)?;
            Ok(ExtractArg::Ref(inst))
        } else {
            deserialize_field_element(py, arg).map(ExtractArg::Owned)
        }
    }
    fn to_ref<'py>(arg: &'py PyRef<Self>) -> &'py Self::Target {
        &arg.inner
    }
    fn to_owned(arg: PyRef<Self>) -> Self::Target {
        arg.inner.to_owned()
    }
}

#[pyclass(name=DomainSeparationTag)]
#[text_signature = "(protocol_id, protocol_version=None, ciphersuite_id=None, encoding_id=None)"]
pub struct PyDomainSeparationTag {
    inner: DomainSeparationTag,
}

#[pymethods]
impl PyDomainSeparationTag {
    #[new]
    fn ctor(
        py: Python,
        protocol_id: &PyAny,
        protocol_version: Option<&PyAny>,
        ciphersuite_id: Option<&PyAny>,
        encoding_id: Option<&PyAny>,
    ) -> PyResult<Self> {
        let protocol_id = copy_buffer_arg(py, protocol_id)?;
        let protocol_version = copy_buffer_opt_arg(py, protocol_version)?;
        let ciphersuite_id = copy_buffer_opt_arg(py, ciphersuite_id)?;
        let encoding_id = copy_buffer_opt_arg(py, encoding_id)?;
        let inner = DomainSeparationTag::new(
            protocol_id.as_ref(),
            protocol_version.as_deref(),
            ciphersuite_id.as_deref(),
            encoding_id.as_deref(),
        )
        .map_err(|e| {
            ValueError::py_err(format!(
                "Error creating domain separation tag: {}",
                e.to_string()
            ))
        })?;
        Ok(Self::new(inner))
    }
}

#[pyproto]
impl PyBufferProtocol for PyDomainSeparationTag {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = slf.inner.to_bytes();
        let py = unsafe { Python::assume_gil_acquired() };
        create_safe_buffer(py, buf, view, flags)
    }

    fn bf_releasebuffer(_slf: PyRefMut<Self>, view: *mut Py_buffer) -> PyResult<()> {
        release_buffer(view)
    }
}

#[pyproto]
impl PyObjectProtocol for PyDomainSeparationTag {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("DomainSeparationTag{:?}", self.inner.to_bytes()))
    }
}

impl PyDomainSeparationTag {
    pub fn new(inner: DomainSeparationTag) -> Self {
        Self { inner }
    }

    pub fn to_owned(&self) -> DomainSeparationTag {
        self.inner.to_owned()
    }
}

impl ParseArg for PyDomainSeparationTag {
    type Target = DomainSeparationTag;
    fn parse_arg<'py>(py: Python<'py>, arg: &'py PyAny) -> PyResult<ExtractArg<'py, Self>> {
        if <Self as PyTypeInfo>::is_instance(arg) {
            let inst = <PyRef<Self> as FromPyObject<'py>>::extract(arg)?;
            Ok(ExtractArg::Ref(inst))
        } else {
            let pid = copy_buffer_arg(py, arg)?;
            Ok(ExtractArg::Owned(
                DomainSeparationTag::new(&pid, None, None, None).map_err(|e| {
                    ValueError::py_err(format!(
                        "Error creating domain separation tag: {}",
                        e.to_string()
                    ))
                })?,
            ))
        }
    }
    fn to_ref<'py>(arg: &'py PyRef<Self>) -> &'py Self::Target {
        &arg.inner
    }
    fn to_owned(arg: PyRef<Self>) -> Self::Target {
        arg.inner.to_owned()
    }
}

#[pyfunction]
/// new_keys(message_count)
/// --
///
/// Create new public and private keys for a number of messages
fn new_keys(message_count: usize) -> PyResult<(PyPublicKey, PySecretKey)> {
    let (pk, sk) = Issuer::new_keys(message_count).map_py_err()?;
    Ok((PyPublicKey::new(pk), PySecretKey::new(sk)))
}

#[pyfunction]
/// new_short_keys(*, seed=None, secret_key=None)
/// --
///
/// Create a new deterministic public key and secret key with an optional seed
fn new_short_keys(
    py: Python,
    seed: Option<&PyAny>,
    secret_key: Option<ExtractArg<PySecretKey>>,
) -> PyResult<(PyDeterministicPublicKey, PySecretKey)> {
    let key_gen = if let Some(seed) = seed {
        let seed = copy_buffer_arg(py, seed)?;
        Some(KeyGenOption::UseSeed(seed))
    } else if let Some(secret_key) = secret_key {
        Some(KeyGenOption::FromSecretKey(secret_key.to_owned()))
    } else {
        None
    };
    let (dpk, sk) = DeterministicPublicKey::new(key_gen);
    Ok((PyDeterministicPublicKey::new(dpk), PySecretKey::new(sk)))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(new_keys))?;
    m.add_wrapped(wrap_pyfunction!(new_short_keys))?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyDeterministicPublicKey>()?;
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyDomainSeparationTag>()?;
    Ok(())
}
