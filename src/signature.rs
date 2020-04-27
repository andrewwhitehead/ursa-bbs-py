use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    BlindSignature, BlindSignatureContext, BlindedSignatureCommitment, Issuer, Prover, Signature,
    SignatureBlinding, SignatureMessage, SignatureNonce, MESSAGE_SIZE,
};

use std::collections::BTreeMap;

use super::buffer::map_buffer_arg;
use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, py_bytes, py_deserialize_compressed, py_serialize_compressed,
    serialize_field_element, ExtractArg,
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
) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
    let message = hash_message_arg(py, message)?;
    let signature_blinding = Signature::generate_blinding();
    let commitment: BlindedSignatureCommitment = &pk.h[0] * &message + &pk.h0 * &signature_blinding;
    Ok((
        py_bytes(py, serialize_field_element(signature_blinding)?),
        py_bytes(py, commitment.to_compressed_bytes().to_vec()),
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
) -> PyResult<(&'py PyBytes, &'py PyBytes)> {
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
    py_serialize_compressed(py, &signature)
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
    py_serialize_compressed(py, &blind_signature)
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
    let context: BlindSignatureContext = py_deserialize_compressed(py, context)?;
    let signing_nonce: SignatureNonce = deserialize_field_element(py, &signing_nonce)?;
    let blind_signature =
        Issuer::blind_sign(&context, &messages, &sk, &pk, &signing_nonce).map_py_err()?;
    py_serialize_compressed(py, &blind_signature)
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
    let signature: BlindSignature = py_deserialize_compressed(py, &signature)?;
    let blinding: SignatureBlinding = deserialize_field_element(py, &blinding)?;
    let unblinded = signature.to_unblinded(&blinding);
    py_serialize_compressed(py, &unblinded)
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
    let signature: Signature = py_deserialize_compressed(py, &signature)?;
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
