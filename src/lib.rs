use pyo3::prelude::*;

mod error;

mod buffer;
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
