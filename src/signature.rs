use bbs::prelude::{
    BlindSignature, BlindSignatureContext, BlindedSignatureCommitment, Issuer, Prover, Signature,
    SignatureBlinding, SignatureMessage, SignatureNonce, MESSAGE_SIZE,
};

use pyo3::exceptions::ValueError;
use pyo3::ffi::Py_buffer;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use std::collections::BTreeMap;
use std::os::raw::c_int;

use super::buffer::map_buffer_arg;
use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, py_bytes, py_deserialize_compressed, py_serialize_compressed,
    serialize_field_element, ExtractArg,
};
use super::keys::{PyPublicKey, PySecretKey};

#[pyclass(name=BlindSignature)]
pub struct PyBlindSignature {
    inner: BlindSignature,
}

py_compressed_bytes_wrapper!(PyBlindSignature, BlindSignature);

#[pyclass(name=Signature)]
pub struct PySignature {
    inner: Signature,
}

py_compressed_bytes_wrapper!(PySignature, Signature);

pub fn hashed_message_arg(
    py: Python,
    arg: &PyAny,
    pre_hashed: Option<bool>,
) -> PyResult<SignatureMessage> {
    let pre_hashed = pre_hashed.unwrap_or(false);
    if pre_hashed {
        deserialize_field_element(py, arg)
    } else {
        map_buffer_arg(py, arg, |data| Ok(SignatureMessage::from_msg_hash(data)))
    }
}

pub fn hashed_message_vec(
    py: Python,
    messages: Vec<&PyAny>,
    pre_hashed: Option<bool>,
) -> PyResult<Vec<SignatureMessage>> {
    messages.into_iter().try_fold(vec![], |mut ms, elt| {
        ms.push(hashed_message_arg(py, elt, pre_hashed)?);
        PyResult::Ok(ms)
    })
}

pub fn hashed_message_btree(
    py: Python,
    messages: BTreeMap<usize, &PyAny>,
    pre_hashed: Option<bool>,
) -> PyResult<BTreeMap<usize, SignatureMessage>> {
    messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hashed_message_arg(py, elt, pre_hashed)?);
            PyResult::Ok(ms)
        })
}

#[pyfunction]
/// create_blinding_commitment(message, pk)
/// --
///
///
fn create_blinding_commitment<'py>(
    py: Python<'py>,
    message: &PyAny,
    pk: ExtractArg<PyPublicKey>,
) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    let message = hashed_message_arg(py, message, None)?;
    let signature_blinding = Signature::generate_blinding();
    let commitment: BlindedSignatureCommitment = &pk.h[0] * &message + &pk.h0 * &signature_blinding;
    Ok((
        py_bytes(py, serialize_field_element(signature_blinding)?),
        py_bytes(py, commitment.to_compressed_bytes().to_vec()),
    ))
}

#[pyfunction]
/// create_blinding_context(messages, pk, signing_nonce, pre_hashed=False)
/// --
///
///
fn create_blinding_context<'py>(
    py: Python<'py>,
    messages: BTreeMap<usize, &PyAny>,
    pk: ExtractArg<PyPublicKey>,
    signing_nonce: &PyAny,
    pre_hashed: Option<bool>,
) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    let messages = hashed_message_btree(py, messages, pre_hashed)?;
    let signing_nonce: SignatureNonce = deserialize_field_element(py, &signing_nonce)?;
    let (ctx, blinding) =
        Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).map_py_err()?;
    Ok((
        py_bytes(py, serialize_field_element(blinding)?),
        py_serialize_compressed(py, &ctx)?,
    ))
}

#[pyfunction]
/// generate_signing_nonce()
/// --
///
/// Generate a new nonce for use in creating a blind signature
fn generate_signing_nonce<'py>(py: Python<'py>) -> PyResult<&'py PyBytes> {
    let nonce = Issuer::generate_signing_nonce();
    Ok(py_bytes(py, serialize_field_element(nonce)?))
}

#[pyfunction]
/// hash_message(message)
/// --
///
/// Create a standard hash for a message to be signed
fn hash_message<'py>(py: Python<'py>, message: &PyAny) -> PyResult<&'py PyBytes> {
    let message = hashed_message_arg(py, message, None)?;
    Ok(py_bytes(py, serialize_field_element(message)?))
}

#[pyfunction]
/// sign_messages(messages, sk, pk, pre_hashed=False)
/// --
///
///
fn sign_messages<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    sk: ExtractArg<PySecretKey>,
    pk: ExtractArg<PyPublicKey>,
    pre_hashed: Option<bool>,
) -> PyResult<PySignature> {
    let messages = hashed_message_vec(py, messages, pre_hashed)?;
    let signature = Signature::new(messages.as_slice(), &*sk, &pk).map_py_err()?;
    Ok(PySignature::new(signature))
}

#[pyfunction]
/// sign_messages_blinded_commitment(messages, sk, pk, commitment, pre_hashed=False)
/// --
///
///
fn sign_messages_blinded_commitment<'py>(
    py: Python<'py>,
    messages: BTreeMap<usize, &PyAny>,
    sk: ExtractArg<PySecretKey>,
    pk: ExtractArg<PyPublicKey>,
    commitment: &PyAny,
    pre_hashed: Option<bool>,
) -> PyResult<PyBlindSignature> {
    let messages = hashed_message_btree(py, messages, pre_hashed)?;
    let commitment = map_buffer_arg(py, commitment, |bytes| {
        if bytes.len() != MESSAGE_SIZE {
            return Err(ValueError::py_err(format!(
                "Invalid commitment value: expected {} bytes, got {}",
                MESSAGE_SIZE,
                bytes.len()
            )));
        }
        let mut deser = [0u8; MESSAGE_SIZE];
        deser.copy_from_slice(bytes);
        Ok(BlindedSignatureCommitment::from(deser))
    })?;
    let blind_signature = BlindSignature::new(&commitment, &messages, &sk, &pk).map_py_err()?;
    Ok(PyBlindSignature::new(blind_signature))
}

#[pyfunction]
/// sign_messages_blinded_context(messages, sk, pk, context, signing_nonce, pre_hashed=False)
/// --
///
///
fn sign_messages_blinded_context<'py>(
    py: Python<'py>,
    messages: BTreeMap<usize, &PyAny>,
    sk: ExtractArg<PySecretKey>,
    pk: ExtractArg<PyPublicKey>,
    context: &PyAny,
    signing_nonce: &PyAny,
    pre_hashed: Option<bool>,
) -> PyResult<PyBlindSignature> {
    let messages = hashed_message_btree(py, messages, pre_hashed)?;
    let context: BlindSignatureContext = py_deserialize_compressed(py, context)?;
    let signing_nonce: SignatureNonce = deserialize_field_element(py, &signing_nonce)?;
    let blind_signature =
        Issuer::blind_sign(&context, &messages, &sk, &pk, &signing_nonce).map_py_err()?;
    Ok(PyBlindSignature::new(blind_signature))
}

#[pyfunction]
/// unblind_signature(signature, blinding)
/// --
///
///
fn unblind_signature<'py>(
    py: Python<'py>,
    signature: ExtractArg<PyBlindSignature>,
    blinding: &PyAny,
) -> PyResult<PySignature> {
    let blinding: SignatureBlinding = deserialize_field_element(py, &blinding)?;
    let unblinded = signature.to_unblinded(&blinding);
    Ok(PySignature::new(unblinded))
}

#[pyfunction]
/// verify_signature(messages, signature, pk, pre_hashed=False)
/// --
///
///
fn verify_signature<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    signature: ExtractArg<PySignature>,
    pk: ExtractArg<PyPublicKey>,
    pre_hashed: Option<bool>,
) -> PyResult<bool> {
    let messages = hashed_message_vec(py, messages, pre_hashed)?;
    signature.verify(messages.as_slice(), &pk).map_py_err()
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_blinding_commitment))?;
    m.add_wrapped(wrap_pyfunction!(create_blinding_context))?;
    m.add_wrapped(wrap_pyfunction!(generate_signing_nonce))?;
    m.add_wrapped(wrap_pyfunction!(hash_message))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages_blinded_commitment))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages_blinded_context))?;
    m.add_wrapped(wrap_pyfunction!(unblind_signature))?;
    m.add_wrapped(wrap_pyfunction!(verify_signature))?;
    m.add_class::<PyBlindSignature>()?;
    m.add_class::<PySignature>()?;
    Ok(())
}
