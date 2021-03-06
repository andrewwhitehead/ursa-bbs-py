use pyo3::prelude::*;

#[macro_use]
mod macros;

mod buffer;
mod error;
mod helpers;
mod keys;
mod proof;
mod signature;

/// BBS+ signature module
#[pymodule]
fn ursa_bbs(py: Python, m: &PyModule) -> PyResult<()> {
    keys::register(py, m)?;
    proof::register(py, m)?;
    signature::register(py, m)?;
    Ok(())
}
