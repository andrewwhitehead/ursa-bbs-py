use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    HiddenMessage, PoKOfSignature, ProofMessage, ProofRequest, Prover, Signature, SignatureNonce,
    SignatureProof, Verifier,
};

use super::error::PyBbsResult;
use super::helpers::{
    deserialize_field_element, deserialize_json_arg, serialize_field_element,
    serialize_json_to_bytes, ExtractArg,
};
use super::keys::PyPublicKey;
use super::signature::hash_message_arg;

#[pyfunction]
/// create_proof_request(reveal_indices, pk)
/// --
///
/// Create new proof request for a sequence of revealed message indices
fn create_proof_request<'py>(
    py: Python<'py>,
    reveal_indices: Vec<usize>,
    pk: ExtractArg<PyPublicKey>,
) -> PyResult<&'py PyBytes> {
    let proof_request = Verifier::new_proof_request(&reveal_indices, &pk).map_py_err()?;
    serialize_json_to_bytes(py, &proof_request)
}

#[pyfunction]
/// commit_signature_pok(messages, reveal_indices, proof_request, signature)
/// --
///
///
fn commit_signature_pok<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    reveal_indices: Vec<usize>,
    proof_request: &PyAny,
    signature: &PyAny,
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
    let proof_request: ProofRequest = deserialize_json_arg(py, proof_request)?;
    let signature: Signature = deserialize_json_arg(py, &signature)?;
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .map_py_err()?;
    serialize_json_to_bytes(py, &pok)
}

#[pyfunction]
/// generate_proof_nonce()
/// --
///
/// Generate a new nonce for sending to a prover
fn generate_proof_nonce() -> PyResult<String> {
    let nonce = Verifier::generate_proof_nonce();
    serialize_field_element(nonce)
}

#[pyfunction]
/// generate_challenge_pok(poks, proof_nonce)
/// --
///
/// Generate a proof challenge from a set of PoKs and a proof nonce
fn generate_challenge_pok<'py>(
    py: Python<'py>,
    poks: Vec<&PyAny>,
    proof_nonce: &PyAny,
) -> PyResult<String> {
    let mut challenge_bytes = vec![];
    for pok_json in poks {
        let pok: PoKOfSignature = deserialize_json_arg(py, pok_json)?;
        challenge_bytes.extend_from_slice(&pok.to_bytes());
    }
    let proof_nonce: SignatureNonce = deserialize_field_element(py, &proof_nonce)?;
    challenge_bytes.extend_from_slice(&proof_nonce.to_bytes());
    let challenge = SignatureNonce::from_msg_hash(&challenge_bytes);
    serialize_field_element(challenge)
}

#[pyfunction]
/// generate_signature_pok(pok, challenge)
/// --
///
///
fn generate_signature_pok<'py>(
    py: Python<'py>,
    pok: &PyAny,
    challenge: &PyAny,
) -> PyResult<&'py PyBytes> {
    let pok: PoKOfSignature = deserialize_json_arg(py, pok)?;
    let challenge: SignatureNonce = deserialize_field_element(py, &challenge)?;
    let proof = Prover::generate_signature_pok(pok, &challenge).map_py_err()?;
    serialize_json_to_bytes(py, &proof)
}

#[pyfunction]
/// verify_signature_pok(proof_request, proof, proof_nonce)
/// --
///
///
fn verify_signature_pok<'py>(
    py: Python<'py>,
    proof_request: &PyAny,
    proof: &PyAny,
    proof_nonce: &PyAny,
) -> PyResult<bool> {
    let proof_request: ProofRequest = deserialize_json_arg(py, proof_request)?;
    let proof: SignatureProof = deserialize_json_arg(py, &proof)?;
    let proof_nonce: SignatureNonce = deserialize_field_element(py, &proof_nonce)?;
    match Verifier::verify_signature_pok(&proof_request, &proof, &proof_nonce) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(commit_signature_pok))?;
    m.add_wrapped(wrap_pyfunction!(create_proof_request))?;
    m.add_wrapped(wrap_pyfunction!(generate_challenge_pok))?;
    m.add_wrapped(wrap_pyfunction!(generate_proof_nonce))?;
    m.add_wrapped(wrap_pyfunction!(generate_signature_pok))?;
    m.add_wrapped(wrap_pyfunction!(verify_signature_pok))?;
    Ok(())
}
