macro_rules! py_compressed_bytes_wrapper {
    ($type:tt, $inner:tt) => {
        #[pymethods]
        impl $type {
            #[new]
            fn ctor(py: pyo3::Python, data: &PyAny) -> PyResult<Self> {
                let inner = <Self as $crate::helpers::ParseArg>::parse_arg(py, data)?.into_owned();
                Ok(Self::new(inner))
            }

            #[text_signature = "()"]
            pub fn to_bytes<'py>(
                slf: pyo3::PyRef<Self>,
                py: Python<'py>,
            ) -> &'py pyo3::types::PyBytes {
                $crate::helpers::py_bytes(py, slf.inner.to_bytes_compressed_form().to_vec())
            }
        }

        #[pyproto]
        impl pyo3::PyBufferProtocol for $type {
            fn bf_getbuffer(
                slf: pyo3::PyRefMut<Self>,
                view: *mut Py_buffer,
                flags: c_int,
            ) -> PyResult<()> {
                let buf = slf.inner.to_bytes_compressed_form().to_vec();
                let py = unsafe { pyo3::Python::assume_gil_acquired() };
                $crate::buffer::create_safe_buffer(py, buf, view, flags)
            }

            fn bf_releasebuffer(
                _slf: pyo3::PyRefMut<Self>,
                view: *mut pyo3::ffi::Py_buffer,
            ) -> PyResult<()> {
                $crate::buffer::release_buffer(view)
            }
        }

        #[pyproto]
        impl pyo3::PyObjectProtocol for $type {
            fn __repr__(&self) -> PyResult<String> {
                Ok(format!("{}({:p})", <$type as pyo3::PyTypeInfo>::NAME, self))
            }
        }

        impl $type {
            pub fn new(inner: $inner) -> Self {
                Self { inner }
            }
        }

        impl std::ops::Deref for $type {
            type Target = $inner;
            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl $crate::helpers::ParseArg for $type {
            type Target = $inner;
            fn parse_arg<'py>(
                py: pyo3::Python<'py>,
                arg: &'py pyo3::PyAny,
            ) -> PyResult<$crate::helpers::ExtractArg<'py, Self>> {
                if <Self as pyo3::PyTypeInfo>::is_instance(arg) {
                    let inst = <pyo3::PyRef<Self> as pyo3::FromPyObject<'py>>::extract(arg)?;
                    Ok($crate::helpers::ExtractArg::Ref(inst))
                } else {
                    $crate::helpers::py_deserialize_try_from(py, arg)
                        .map($crate::helpers::ExtractArg::Owned)
                }
            }
            fn to_ref<'py>(arg: &'py pyo3::PyRef<Self>) -> &'py Self::Target {
                &arg.inner
            }
            fn to_owned(arg: pyo3::PyRef<Self>) -> Self::Target {
                arg.inner.to_owned()
            }
        }
    };
}
