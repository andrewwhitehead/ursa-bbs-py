use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::BufferError;
use pyo3::ffi::{PyBUF_FORMAT, PyBUF_ND, PyBUF_STRIDES, PyBUF_WRITABLE, Py_INCREF, Py_buffer};
use pyo3::prelude::*;
use pyo3::AsPyPointer;

use zeroize::Zeroize;

pub fn copy_buffer_arg(py: Python, data: &PyAny) -> PyResult<Vec<u8>> {
    let buffer = PyBuffer::get(py, data)?;
    buffer.to_vec(py)
}

pub fn copy_buffer_opt_arg(py: Python, arg: Option<&PyAny>) -> PyResult<Option<Vec<u8>>> {
    arg.map(|buf| copy_buffer_arg(py, buf)).transpose()
}

pub fn map_buffer_arg<T, F>(py: Python, data: &PyAny, map_fn: F) -> PyResult<T>
where
    F: FnOnce(&[u8]) -> PyResult<T>,
{
    let buffer = PyBuffer::get(py, data)?;
    let data =
        unsafe { std::slice::from_raw_parts(buffer.buf_ptr() as *mut u8, buffer.len_bytes()) };
    map_fn(data)
}

pub fn create_safe_buffer(
    py: Python,
    bytes: Vec<u8>,
    view: *mut Py_buffer,
    flags: c_int,
) -> PyResult<()> {
    let buf = PySafeBuffer::new(bytes);
    let cell = PyCell::new(py, buf)?;
    let container = cell.borrow_mut();
    export_buffer(container.as_ptr(), container.as_ref(), view, flags)
}

pub fn export_buffer(
    container: *mut pyo3::ffi::PyObject,
    bytes: &[u8],
    view: *mut Py_buffer,
    flags: c_int,
) -> PyResult<()> {
    if view.is_null() {
        return Err(BufferError::py_err("View is null"));
    }
    if (flags & PyBUF_WRITABLE) == PyBUF_WRITABLE {
        return Err(BufferError::py_err("Object is not writable"));
    }

    unsafe {
        // debug!("create memory view {:p}", &bytes);
        (*view).obj = container;
        Py_INCREF((*view).obj);

        (*view).buf = bytes.as_ptr() as *mut c_void;
        (*view).len = bytes.len() as isize;
        (*view).readonly = 1;
        (*view).itemsize = 1;

        (*view).format = ptr::null_mut();
        if (flags & PyBUF_FORMAT) == PyBUF_FORMAT {
            let msg = CStr::from_bytes_with_nul(b"B\0").unwrap();
            (*view).format = msg.as_ptr() as *mut _;
        }

        (*view).ndim = 1;
        (*view).shape = ptr::null_mut();
        if (flags & PyBUF_ND) == PyBUF_ND {
            (*view).shape = (&((*view).len)) as *const _ as *mut _;
        }

        (*view).strides = ptr::null_mut();
        if (flags & PyBUF_STRIDES) == PyBUF_STRIDES {
            (*view).strides = &((*view).itemsize) as *const _ as *mut _;
        }

        (*view).suboffsets = ptr::null_mut();
        (*view).internal = ptr::null_mut();
    }
    Ok(())
}

pub fn release_buffer(view: *mut Py_buffer) -> PyResult<()> {
    if view.is_null() {
        return Err(BufferError::py_err("View is null"));
    }
    // Python will have already decreased the reference count of view.obj
    Ok(())
}

#[pyclass(name=SafeBuffer)]
pub struct PySafeBuffer {
    inner: Vec<u8>,
}

impl PySafeBuffer {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { inner: buf }
    }
}

impl AsRef<[u8]> for PySafeBuffer {
    fn as_ref(&self) -> &[u8] {
        return self.inner.as_ref();
    }
}

impl Drop for PySafeBuffer {
    fn drop(&mut self) {
        // debug!("zero buffer {:p}", &self.inner);
        self.inner.zeroize()
    }
}
