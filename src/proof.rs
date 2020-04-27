use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    HiddenMessage, PoKOfSignatureProof, ProofMessage, Prover, Signature, SignatureNonce,
    SignatureProof, Verifier,
};

use std::collections::BTreeMap;

use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, py_bytes, py_deserialize_compressed, py_serialize_compressed,
    serialize_field_element, ExtractArg,
};
use super::keys::PyPublicKey;
use super::signature::hash_message_arg;

#[pyfunction]
/// create_proof(messages, reveal_indices, pk, signature, proof_nonce=None)
/// --
///
///
fn create_proof<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    reveal_indices: Vec<usize>,
    pk: ExtractArg<PyPublicKey>,
    signature: &PyAny,
    proof_nonce: Option<&PyAny>,
) -> PyResult<&'py PyBytes> {
    let proof_messages =
        messages
            .into_iter()
            .enumerate()
            .try_fold(vec![], |mut ms, (idx, elt)| {
                let hash = hash_message_arg(py, elt)?;
                let message = if reveal_indices.contains(&idx) {
                    ProofMessage::Revealed(hash)
                } else {
                    ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(hash))
                };
                ms.push(message);
                PyResult::Ok(ms)
            })?;
    let proof_request = Verifier::new_proof_request(&reveal_indices, &pk).map_py_err()?;
    let signature: Signature = py_deserialize_compressed(py, &signature)?;
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .map_py_err()?;
    let mut challenge_bytes = vec![];
    challenge_bytes.extend_from_slice(&pok.to_bytes());
    let proof_nonce = if let Some(proof_nonce) = proof_nonce {
        deserialize_field_element(py, &proof_nonce)?
    } else {
        SignatureNonce::new()
    };
    challenge_bytes.extend_from_slice(&proof_nonce.to_bytes());
    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);
    let proof = pok.gen_proof(&challenge).map_py_err()?;
    py_serialize_compressed(py, &proof)
}

#[pyfunction]
/// generate_proof_nonce()
/// --
///
/// Generate a new nonce for sending to a prover
fn generate_proof_nonce<'py>(py: Python<'py>) -> PyResult<&'py PyBytes> {
    let nonce = Verifier::generate_proof_nonce();
    Ok(py_bytes(py, serialize_field_element(nonce)?))
}

#[pyfunction]
/// verify_signature_pok(messages, revealed_indices, pk, proof, proof_nonce=None)
/// --
///
/// Verify a signature proof
fn verify_proof<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    revealed_indices: Vec<usize>,
    pk: ExtractArg<PyPublicKey>,
    proof: &PyAny,
    proof_nonce: Option<&PyAny>,
) -> PyResult<bool> {
    let proof_request = Verifier::new_proof_request(&revealed_indices, &pk).map_py_err()?;
    let proof: PoKOfSignatureProof = py_deserialize_compressed(py, &proof)?;
    let proof_nonce = if let Some(proof_nonce) = proof_nonce {
        deserialize_field_element(py, &proof_nonce)?
    } else {
        SignatureNonce::new()
    };
    if revealed_indices.len() > messages.len() {
        return Err(ValueError::py_err(
            "Revealed indices outnumber revealed messages",
        ));
    }
    let revealed_messages =
        messages
            .into_iter()
            .enumerate()
            .try_fold(BTreeMap::new(), |mut ms, (idx, elt)| {
                let rev_idx = revealed_indices[idx];
                if ms.contains_key(&rev_idx) {
                    return Err(ValueError::py_err("Duplicate revealed message index"));
                }
                ms.insert(rev_idx, hash_message_arg(py, elt)?);
                PyResult::Ok(ms)
            })?;
    let signature_proof = SignatureProof {
        revealed_messages,
        proof,
    };
    match Verifier::verify_signature_pok(&proof_request, &signature_proof, &proof_nonce) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_proof))?;
    m.add_wrapped(wrap_pyfunction!(generate_proof_nonce))?;
    m.add_wrapped(wrap_pyfunction!(verify_proof))?;
    Ok(())
}
