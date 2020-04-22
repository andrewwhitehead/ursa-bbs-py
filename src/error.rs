use pyo3::create_exception;
use pyo3::exceptions::Exception;
use pyo3::prelude::*;

create_exception!(ursa_bbs, BbsError, Exception);

pub trait PyBbsResult<T> {
    fn map_py_err(self) -> PyResult<T>;
}

impl<T> PyBbsResult<T> for Result<T, bbs::prelude::BBSError> {
    fn map_py_err(self) -> PyResult<T> {
        match self {
            Ok(r) => Ok(r),
            Err(err) => Err(PyErr::new::<BbsError, _>(err.to_string())),
        }
    }
}

impl<T> PyBbsResult<T> for Result<T, serde_json::Error> {
    fn map_py_err(self) -> PyResult<T> {
        match self {
            Ok(r) => Ok(r),
            Err(err) => Err(PyErr::new::<BbsError, _>(format!(
                "Error serializing JSON: {}",
                err
            ))),
        }
    }
}
