use pyo3::prelude::*;

mod buffer;
mod keys;
mod signature;

/// BBS+ signature module
#[pymodule]
fn ursa_bbs(py: Python, m: &PyModule) -> PyResult<()> {
    keys::register(py, m)?;
    signature::register(py, m)?;
    Ok(())
}
