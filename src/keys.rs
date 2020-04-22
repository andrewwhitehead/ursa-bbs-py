use std::os::raw::c_int;

use pyo3::buffer::PyBuffer;
use pyo3::class::{PyBufferProtocol, PyObjectProtocol};
use pyo3::exceptions::{Exception, ValueError};
use pyo3::ffi::Py_buffer;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::{wrap_pyfunction, PyRefMut, PyTypeInfo};

use bbs::prelude::{
    DeterministicPublicKey, DomainSeparationTag, Issuer, KeyGenOption, PublicKey, SecretKey,
    PUBLIC_KEY_SIZE,
};

use super::buffer::{
    copy_buffer_arg, copy_buffer_arg_to_slice, copy_buffer_opt_arg, create_buffer, release_buffer,
    serialize_json_to_bytes,
};

#[pyclass(name=PublicKey)]
pub struct PyPublicKey {
    inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        let buffer = PyBuffer::get(py, data)?;
        let data =
            unsafe { std::slice::from_raw_parts(buffer.buf_ptr() as *mut u8, buffer.len_bytes()) };
        // FIXME does this panic if the buffer size is wrong?
        let inner = PublicKey::from_bytes(data).map_err(|e| {
            PyErr::new::<ValueError, _>(format!(
                "Error deserializing public key: {}",
                e.to_string()
            ))
        })?;
        Ok(Self::new(inner))
    }

    pub fn to_json<'py>(slf: PyRef<Self>, py: Python<'py>) -> PyResult<&'py PyBytes> {
        serialize_json_to_bytes(py, &slf.inner)
    }
}

#[pyproto]
impl PyBufferProtocol for PyPublicKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = slf.inner.to_bytes();
        println!("pk len {}", buf.len());
        let py = unsafe { Python::assume_gil_acquired() };
        create_buffer(py, buf, view, flags)
    }

    fn bf_releasebuffer(_slf: PyRefMut<Self>, view: *mut Py_buffer) -> PyResult<()> {
        release_buffer(view)
    }
}

#[pyproto]
impl PyObjectProtocol for PyPublicKey {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("PublicKey({:p})", self))
    }
}

impl PyPublicKey {
    pub fn new(inner: PublicKey) -> Self {
        Self { inner }
    }
}

impl std::ops::Deref for PyPublicKey {
    type Target = PublicKey;
    fn deref(&self) -> &PublicKey {
        &self.inner
    }
}

#[pyclass(name=DeterministicPublicKey)]
pub struct PyDeterministicPublicKey {
    inner: DeterministicPublicKey,
}

#[pymethods]
impl PyDeterministicPublicKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        if <PySecretKey as PyTypeInfo>::is_instance(data) {
            let skref = <PyRef<PySecretKey> as FromPyObject>::extract(data)?;
            let (dpk, _sk) =
                DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(skref.to_owned())));
            Ok(PyDeterministicPublicKey::new(dpk))
        } else {
            let mut data_cpy = [0u8; PUBLIC_KEY_SIZE];
            copy_buffer_arg_to_slice(py, data, &mut data_cpy)?;
            let inner = DeterministicPublicKey::from_bytes(data_cpy);
            Ok(Self::new(inner))
        }
    }

    pub fn to_public_key(
        &self,
        py: Python,
        message_count: usize,
        dst: &PyAny,
    ) -> PyResult<PyPublicKey> {
        let dst = if <PyDomainSeparationTag as PyTypeInfo>::is_instance(dst) {
            let dstref = <PyRef<PyDomainSeparationTag> as FromPyObject>::extract(dst)?;
            dstref.to_owned()
        } else {
            let dst_bytes = copy_buffer_arg(py, dst)?;
            DomainSeparationTag::new(dst_bytes.as_ref(), None, None, None).map_err(|e|
                // FIXME add custom exception type
                PyErr::new::<Exception, _>(format!("Error creating domain separation tag: {}", e.to_string()))
            )?
        };
        let pk = (&self.inner)
            .to_public_key(message_count, dst.to_owned())
            .map_err(|e|
                // FIXME add custom exception type
                PyErr::new::<Exception, _>(format!("Error creating public key: {}", e.to_string())),
            )?;
        Ok(PyPublicKey::new(pk))
    }
}

#[pyproto]
impl PyBufferProtocol for PyDeterministicPublicKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = slf.inner.to_bytes().to_vec();
        let py = unsafe { Python::assume_gil_acquired() };
        create_buffer(py, buf, view, flags)
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

#[pyclass(name=SecretKey)]
pub struct PySecretKey {
    inner: SecretKey,
}

#[pymethods]
impl PySecretKey {
    #[new]
    fn ctor(py: Python, data: &PyAny) -> PyResult<Self> {
        let buffer = PyBuffer::get(py, data)?;
        let data =
            unsafe { std::slice::from_raw_parts(buffer.buf_ptr() as *mut u8, buffer.len_bytes()) };
        let inner = SecretKey::from_bytes(data).map_err(|e| {
            PyErr::new::<ValueError, _>(format!(
                "Error deserializing secret key: {}",
                e.to_string()
            ))
        })?;
        Ok(Self::new(inner))
    }
}

#[pyproto]
impl PyBufferProtocol for PySecretKey {
    fn bf_getbuffer(slf: PyRefMut<Self>, view: *mut Py_buffer, flags: c_int) -> PyResult<()> {
        let buf = slf.inner.to_bytes();
        let py = unsafe { Python::assume_gil_acquired() };
        create_buffer(py, buf, view, flags)
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

#[pyclass(name=DomainSeparationTag)]
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
            PyErr::new::<ValueError, _>(format!(
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
        create_buffer(py, buf, view, flags)
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

#[pyfunction]
fn new_keys(message_count: usize) -> PyResult<(PyPublicKey, PySecretKey)> {
    let (pk, sk) = Issuer::new_keys(message_count).map_err(|e| {
        // FIXME add custom exception type
        PyErr::new::<Exception, _>(format!("Error creating keypair: {}", e.to_string()))
    })?;
    Ok((PyPublicKey::new(pk), PySecretKey::new(sk)))
}

#[pyfunction]
fn new_short_keys(
    py: Python,
    seed: Option<&PyAny>,
) -> PyResult<(PyDeterministicPublicKey, PySecretKey)> {
    let key_gen = seed
        .map(|seed| copy_buffer_arg(py, seed))
        .transpose()?
        .map(|seed| KeyGenOption::UseSeed(seed));
    let (dpk, sk) = DeterministicPublicKey::new(key_gen);
    Ok((PyDeterministicPublicKey::new(dpk), PySecretKey::new(sk)))
}

#[pyfunction]
pub fn short_key_from_secret_key(key: PyRef<PySecretKey>) -> PyResult<PyDeterministicPublicKey> {
    let sk = key.to_owned();
    let (dpk, _sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
    Ok(PyDeterministicPublicKey::new(dpk))
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(new_keys))?;
    m.add_wrapped(wrap_pyfunction!(new_short_keys))?;
    m.add_wrapped(wrap_pyfunction!(short_key_from_secret_key))?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyDeterministicPublicKey>()?;
    m.add_class::<PySecretKey>()?;
    m.add_class::<PyDomainSeparationTag>()?;
    Ok(())
}
