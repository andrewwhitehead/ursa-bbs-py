use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    BlindSignature, BlindSignatureContext, BlindedSignatureCommitment, Issuer, Prover, Signature,
    SignatureBlinding, SignatureMessage, SignatureNonce,
};

use std::collections::BTreeMap;

use super::buffer::map_buffer_arg;
use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, deserialize_group_element, deserialize_json_arg,
    serialize_field_element, serialize_group_element, serialize_json_to_bytes, ExtractArg,
};
use super::keys::{PyPublicKey, PySecretKey};

pub fn hash_message_arg(py: Python, arg: &PyAny) -> PyResult<SignatureMessage> {
    map_buffer_arg(py, arg, |data| Ok(SignatureMessage::from_msg_hash(data)))
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
) -> PyResult<(String, String)> {
    let message = hash_message_arg(py, message)?;
    let signature_blinding = Signature::generate_blinding();
    let commitment: BlindedSignatureCommitment = &pk.h[0] * &message + &pk.h0 * &signature_blinding;
    Ok((
        serialize_field_element(signature_blinding)?,
        serialize_group_element(commitment)?,
    ))
}

#[pyfunction]
/// create_blinding_context(messages, pk, signing_nonce)
/// --
///
///
fn create_blinding_context<'py>(
    py: Python<'py>,
    messages: BTreeMap<usize, &PyAny>,
    pk: ExtractArg<PyPublicKey>,
    signing_nonce: &PyAny,
) -> PyResult<(String, &'py PyBytes)> {
    let messages = messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hash_message_arg(py, elt)?);
            PyResult::Ok(ms)
        })?;
    let signing_nonce: SignatureNonce = deserialize_field_element(py, &signing_nonce)?;
    let (ctx, blinding) =
        Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).map_py_err()?;
    Ok((
        serialize_field_element(blinding)?,
        serialize_json_to_bytes(py, &ctx)?,
    ))
}

#[pyfunction]
/// generate_signing_nonce()
/// --
///
/// Generate a new nonce for use in creating a blind signature
fn generate_signing_nonce() -> PyResult<String> {
    let nonce = Issuer::generate_signing_nonce();
    serialize_field_element(nonce)
}

#[pyfunction]
/// sign_messages(messages, sk, pk)
/// --
///
///
fn sign_messages<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    sk: ExtractArg<PySecretKey>,
    pk: ExtractArg<PyPublicKey>,
) -> PyResult<&'py PyBytes> {
    let messages = messages.into_iter().try_fold(vec![], |mut ms, elt| {
        ms.push(hash_message_arg(py, elt)?);
        PyResult::Ok(ms)
    })?;
    let signature = Signature::new(messages.as_slice(), &*sk, &pk).map_py_err()?;
    serialize_json_to_bytes(py, &signature)
}

#[pyfunction]
/// sign_messages_blinded_commitment(messages, sk, pk, commitment)
/// --
///
///
fn sign_messages_blinded_commitment<'py>(
    py: Python<'py>,
    messages: BTreeMap<usize, &PyAny>,
    sk: ExtractArg<PySecretKey>,
    pk: ExtractArg<PyPublicKey>,
    commitment: &PyAny,
) -> PyResult<&'py PyBytes> {
    let messages = messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hash_message_arg(py, elt)?);
            PyResult::Ok(ms)
        })?;
    let commitment: BlindedSignatureCommitment = deserialize_group_element(py, commitment)?;
    let blind_signature = BlindSignature::new(&commitment, &messages, &sk, &pk).map_py_err()?;
    serialize_json_to_bytes(py, &blind_signature)
}

#[pyfunction]
/// sign_messages_blinded_context(messages, sk, pk, context, signing_nonce)
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
) -> PyResult<&'py PyBytes> {
    let messages = messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hash_message_arg(py, elt)?);
            PyResult::Ok(ms)
        })?;
    let context: BlindSignatureContext = deserialize_json_arg(py, context)?;
    let signing_nonce: SignatureNonce = deserialize_field_element(py, &signing_nonce)?;
    let blind_signature =
        Issuer::blind_sign(&context, &messages, &sk, &pk, &signing_nonce).map_py_err()?;
    serialize_json_to_bytes(py, &blind_signature)
}

#[pyfunction]
/// unblind_signature(signature, blinding)
/// --
///
///
fn unblind_signature<'py>(
    py: Python<'py>,
    signature: &PyAny,
    blinding: &PyAny,
) -> PyResult<&'py PyBytes> {
    let signature: BlindSignature = deserialize_json_arg(py, &signature)?;
    let blinding: SignatureBlinding = deserialize_field_element(py, &blinding)?;
    let unblinded = signature.to_unblinded(&blinding);
    serialize_json_to_bytes(py, &unblinded)
}

#[pyfunction]
/// verify_signature(messages, signature, pk)
/// --
///
///
fn verify_signature<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    signature: &PyAny,
    pk: ExtractArg<PyPublicKey>,
) -> PyResult<bool> {
    let messages = messages.into_iter().try_fold(vec![], |mut ms, elt| {
        ms.push(hash_message_arg(py, elt)?);
        PyResult::Ok(ms)
    })?;
    let signature: Signature = deserialize_json_arg(py, &signature)?;
    signature.verify(messages.as_slice(), &pk).map_py_err()
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_blinding_commitment))?;
    m.add_wrapped(wrap_pyfunction!(create_blinding_context))?;
    m.add_wrapped(wrap_pyfunction!(generate_signing_nonce))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages_blinded_commitment))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages_blinded_context))?;
    m.add_wrapped(wrap_pyfunction!(unblind_signature))?;
    m.add_wrapped(wrap_pyfunction!(verify_signature))?;
    Ok(())
}
