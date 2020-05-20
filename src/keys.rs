use bbs::prelude::{
    DeterministicPublicKey, KeyGenOption, PublicKey, SecretKey, ToVariableLengthBytes,
};

use pyo3::class::{PyBufferProtocol, PyObjectProtocol};
use pyo3::ffi::Py_buffer;
use pyo3::prelude::*;
use pyo3::{wrap_pyfunction, PyRefMut, PyTypeInfo};

use std::os::raw::c_int;

use super::buffer::{copy_buffer_arg, create_safe_buffer, release_buffer};
use super::error::PyBbsResult;
use super::helpers::{py_bytes, py_deserialize_try_from, ExtractArg, ParseArg};

#[pyclass(name=PublicKey)]
pub struct PyPublicKey {
    inner: PublicKey,
}

py_compressed_bytes_wrapper!(PyPublicKey, PublicKey);

#[pyclass(name=BlsPublicKey)]
pub struct PyBlsPublicKey {
    inner: DeterministicPublicKey,
}

#[pymethods]
impl PyBlsPublicKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        let inner = <Self as ParseArg>::parse_arg(py, data)?.into_owned();
        Ok(Self::new(inner))
    }

    /// Create a new public key given the message count
    #[text_signature = "(message_count)"]
    pub fn to_public_key(&self, message_count: usize) -> PyResult<PyPublicKey> {
        let pk = (&self.inner).to_public_key(message_count).map_py_err()?;
        Ok(PyPublicKey::new(pk))
    }

    #[text_signature = "()"]
    pub fn to_bytes<'py>(slf: pyo3::PyRef<Self>, py: Python<'py>) -> &'py pyo3::types::PyBytes {
        py_bytes(py, slf.inner.to_bytes_compressed_form().to_vec())
    }
}

#[pyproto]
impl PyBufferProtocol for PyBlsPublicKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = slf.inner.to_bytes_compressed_form().to_vec();
        let py = unsafe { Python::assume_gil_acquired() };
        create_safe_buffer(py, buf, view, flags)
    }

    fn bf_releasebuffer(_slf: PyRefMut<Self>, view: *mut Py_buffer) -> PyResult<()> {
        release_buffer(view)
    }
}

#[pyproto]
impl PyObjectProtocol for PyBlsPublicKey {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("DeterministicPublicKey({:p})", self))
    }
}

impl PyBlsPublicKey {
    pub fn new(inner: DeterministicPublicKey) -> Self {
        Self { inner }
    }
}

impl std::ops::Deref for PyBlsPublicKey {
    type Target = DeterministicPublicKey;
    fn deref(&self) -> &DeterministicPublicKey {
        &self.inner
    }
}

impl ParseArg for PyBlsPublicKey {
    type Target = DeterministicPublicKey;
    fn parse_arg<'py>(py: Python<'py>, arg: &'py PyAny) -> PyResult<ExtractArg<'py, Self>> {
        if <PyBlsSecretKey as PyTypeInfo>::is_instance(arg) {
            let skref = <PyRef<PyBlsSecretKey> as FromPyObject>::extract(arg)?;
            let (dpk, _sk) =
                DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(skref.to_owned())));
            Ok(ExtractArg::Owned(dpk))
        } else if <Self as PyTypeInfo>::is_instance(arg) {
            let inst = <PyRef<Self> as FromPyObject<'py>>::extract(arg)?;
            Ok(ExtractArg::Ref(inst))
        } else {
            py_deserialize_try_from(py, arg).map(ExtractArg::Owned)
        }
    }
    fn to_ref<'py>(arg: &'py PyRef<Self>) -> &'py Self::Target {
        &arg.inner
    }
    fn to_owned(arg: PyRef<Self>) -> Self::Target {
        arg.inner.to_owned()
    }
}

#[pyclass(name=BlsSecretKey)]
pub struct PyBlsSecretKey {
    inner: SecretKey,
}

py_compressed_bytes_wrapper!(PyBlsSecretKey, SecretKey);

#[pyfunction]
/// generate_bls_keypair(*, seed=None, secret_key=None)
/// --
///
/// Create a new deterministic public key and secret key with an optional seed
fn generate_bls_keypair(
    py: Python,
    seed: Option<&PyAny>,
    secret_key: Option<ExtractArg<PyBlsSecretKey>>,
) -> PyResult<(PyBlsPublicKey, PyBlsSecretKey)> {
    let key_gen = if let Some(seed) = seed {
        let seed = copy_buffer_arg(py, seed)?;
        Some(KeyGenOption::UseSeed(seed))
    } else if let Some(secret_key) = secret_key {
        Some(KeyGenOption::FromSecretKey(secret_key.to_owned()))
    } else {
        None
    };
    let (dpk, sk) = DeterministicPublicKey::new(key_gen);
    Ok((PyBlsPublicKey::new(dpk), PyBlsSecretKey::new(sk)))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(generate_bls_keypair))?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyBlsPublicKey>()?;
    m.add_class::<PyBlsSecretKey>()?;
    Ok(())
}
