use pyo3::exceptions::{Exception, ValueError};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    BlindSignature, BlindedSignatureCommitment, GroupElement, Prover, Signature, SignatureBlinding,
    SignatureMessage, SignatureNonce, SIGNATURE_SIZE,
};

use std::collections::BTreeMap;

use super::buffer::{copy_buffer_arg_to_slice, map_buffer_arg};
use super::keys::{PyPublicKey, PySecretKey};

fn hash_message_arg(py: Python, arg: &PyAny) -> PyResult<SignatureMessage> {
    map_buffer_arg(py, arg, |data| Ok(SignatureMessage::from_msg_hash(data)))
}

#[pyfunction]
fn create_blinding_commitment(
    py: Python,
    message: &PyAny,
    pk: PyRef<PyPublicKey>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let message = hash_message_arg(py, message)?;
    let signature_blinding = Signature::generate_blinding();
    let commitment: BlindedSignatureCommitment = &pk.h[0] * &message + &pk.h0 * &signature_blinding;
    Ok((signature_blinding.to_bytes(), commitment.to_bytes()))
}

#[pyfunction]
fn create_blinding_context(
    py: Python,
    messages: BTreeMap<usize, &PyAny>,
    pk: PyRef<PyPublicKey>,
    issuer_nonce: &PyAny,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let messages = messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hash_message_arg(py, elt)?);
            PyResult::Ok(ms)
        })?;
    let issuer_nonce = map_buffer_arg(py, issuer_nonce, |bytes| {
        SignatureNonce::from_bytes(bytes).map_err(|e| {
            PyErr::new::<ValueError, _>(format!("Invalid signing nonce: {}", e.to_string()))
        })
    })?;
    let (ctx, blinding) = Prover::new_blind_signature_context(&pk, &messages, &issuer_nonce)
        .map_err(|e|
        // FIXME add custom exception type
        PyErr::new::<Exception, _>(format!("Error creating blinding context: {}", e.to_string())))?;
    Ok((blinding.to_bytes(), ctx.to_bytes()))
}

#[pyfunction]
fn sign_messages(
    py: Python,
    messages: Vec<&PyAny>,
    sk: PyRef<PySecretKey>,
    pk: PyRef<PyPublicKey>,
) -> PyResult<Vec<u8>> {
    let messages = messages.into_iter().try_fold(vec![], |mut ms, elt| {
        ms.push(hash_message_arg(py, elt)?);
        PyResult::Ok(ms)
    })?;
    let signature = Signature::new(messages.as_slice(), &*sk, &*pk).map_err(|e|
        // FIXME add custom exception type
        PyErr::new::<Exception, _>(format!("Error creating signature: {}", e.to_string())))?;
    Ok(signature.to_bytes().to_vec())
}

#[pyfunction]
fn sign_messages_blinded(
    py: Python,
    messages: BTreeMap<usize, &PyAny>,
    sk: PyRef<PySecretKey>,
    pk: PyRef<PyPublicKey>,
    commitment: &PyAny,
) -> PyResult<Vec<u8>> {
    let messages = messages
        .into_iter()
        .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
            ms.insert(idx, hash_message_arg(py, elt)?);
            PyResult::Ok(ms)
        })?;
    let commitment = map_buffer_arg(py, commitment, |bytes| {
        BlindedSignatureCommitment::from_bytes(bytes).map_err(|e| {
            PyErr::new::<ValueError, _>(format!("Invalid blinded commitment: {}", e.to_string()))
        })
    })?;
    let blind_signature = BlindSignature::new(&commitment, &messages, &sk, &pk).map_err(|e|
        // FIXME add custom exception type
        PyErr::new::<Exception, _>(format!("Error creating blinded signature: {}", e.to_string())))?;
    Ok(blind_signature.to_bytes().to_vec())
}

#[pyfunction]
fn unblind_signature(py: Python, signature: &PyAny, blinding: &PyAny) -> PyResult<Vec<u8>> {
    let mut sig = [0u8; SIGNATURE_SIZE];
    copy_buffer_arg_to_slice(py, signature, &mut sig)?;
    let sig = BlindSignature::from_bytes(sig);
    let blinding = map_buffer_arg(py, blinding, |bytes| {
        SignatureBlinding::from_bytes(bytes).map_err(|e| {
            PyErr::new::<ValueError, _>(format!("Invalid signature blinding: {}", e.to_string()))
        })
    })?;
    let unblinded = sig.to_unblinded(&blinding);
    Ok(unblinded.to_bytes().to_vec())
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_blinding_commitment))?;
    m.add_wrapped(wrap_pyfunction!(create_blinding_context))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages))?;
    m.add_wrapped(wrap_pyfunction!(sign_messages_blinded))?;
    m.add_wrapped(wrap_pyfunction!(unblind_signature))?;
    Ok(())
}
