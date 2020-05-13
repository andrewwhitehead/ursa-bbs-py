use pyo3::exceptions::ValueError;
use pyo3::ffi::Py_buffer;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use bbs::prelude::{
    HashElem, HiddenMessage, PoKOfSignatureProof, ProofChallenge, ProofMessage, ProofNonce, Prover,
    RandomElem, SignatureProof, ToVariableLengthBytes, Verifier,
};

use std::collections::BTreeMap;
use std::os::raw::c_int;

use super::error::PyBbsResult;
use super::helpers::{py_bytes, py_deserialize_try_from, ExtractArg};
use super::keys::PyPublicKey;
use super::signature::{hashed_message_arg, PySignature};

#[pyclass(name=Proof)]
pub struct PyProof {
    inner: PoKOfSignatureProof,
}

py_compressed_bytes_wrapper!(PyProof, PoKOfSignatureProof);

#[pyfunction]
/// create_proof(messages, reveal_indices, pk, signature, proof_nonce=None, pre_hashed=False)
/// --
///
///
fn create_proof<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    reveal_indices: Vec<usize>,
    pk: ExtractArg<PyPublicKey>,
    signature: ExtractArg<PySignature>,
    proof_nonce: Option<&PyAny>,
    pre_hashed: Option<bool>,
) -> PyResult<PyProof> {
    let proof_messages =
        messages
            .into_iter()
            .enumerate()
            .try_fold(vec![], |mut ms, (idx, elt)| {
                let hash = hashed_message_arg(py, elt, pre_hashed)?;
                let message = if reveal_indices.contains(&idx) {
                    ProofMessage::Revealed(hash)
                } else {
                    ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(hash))
                };
                ms.push(message);
                PyResult::Ok(ms)
            })?;
    let proof_request = Verifier::new_proof_request(&reveal_indices, &pk).map_py_err()?;
    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .map_py_err()?;
    let mut challenge_bytes = vec![];
    challenge_bytes.extend_from_slice(&pok.to_bytes());
    let proof_nonce = if let Some(proof_nonce) = proof_nonce {
        py_deserialize_try_from(py, &proof_nonce)?
    } else {
        ProofNonce::random()
    };
    challenge_bytes.extend_from_slice(&proof_nonce.to_bytes_compressed_form());
    let challenge = ProofChallenge::hash(&challenge_bytes);
    let proof = pok.gen_proof(&challenge).map_py_err()?;
    Ok(PyProof::new(proof))
}

#[pyfunction]
/// generate_proof_nonce()
/// --
///
/// Generate a new nonce for sending to a prover
fn generate_proof_nonce<'py>(py: Python<'py>) -> PyResult<&'py PyBytes> {
    let nonce = ProofNonce::random();
    Ok(py_bytes(py, nonce.to_bytes_compressed_form()))
}

#[pyfunction]
/// verify_signature_pok(messages, revealed_indices, pk, proof, proof_nonce=None, pre_hashed=False)
/// --
///
/// Verify a signature proof
fn verify_proof<'py>(
    py: Python<'py>,
    messages: Vec<&PyAny>,
    revealed_indices: Vec<usize>,
    pk: ExtractArg<PyPublicKey>,
    proof: ExtractArg<PyProof>,
    proof_nonce: Option<&PyAny>,
    pre_hashed: Option<bool>,
) -> PyResult<bool> {
    let proof_request = Verifier::new_proof_request(&revealed_indices, &pk).map_py_err()?;
    let proof_nonce = if let Some(proof_nonce) = proof_nonce {
        py_deserialize_try_from(py, &proof_nonce)?
    } else {
        ProofNonce::random()
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
                ms.insert(rev_idx, hashed_message_arg(py, elt, pre_hashed)?);
                PyResult::Ok(ms)
            })?;
    let signature_proof = SignatureProof {
        revealed_messages,
        proof: proof.into_owned(),
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
    m.add_class::<PyProof>()?;
    Ok(())
}
