use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyTuple};
use pyo3::{wrap_pyfunction, FromPyObject, IntoPy, PyObject};
use schnorrkel::context::signing_context;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey, PublicKey, SecretKey, Keypair as SchnorrkelKeypair};
use schnorrkel::sign::{Signature};
use schnorrkel::derive::{CHAIN_CODE_LENGTH, Derivation, ChainCode};

const SIGNING_CTX: &'static [u8] = b"substrate";

pub struct Seed([u8; 32]);
pub struct Keypair([u8; 32], [u8; 64]);
pub struct PubKey([u8; 32]);
pub struct Sig([u8; 64]);
pub struct Message(Vec<u8>);
pub struct ExtendedPubKey([u8; CHAIN_CODE_LENGTH], [u8; 32]);
pub struct ExtendedKeypair([u8; CHAIN_CODE_LENGTH], [u8; 32], [u8; 64]);


// Helper functions
fn _check_pybytes_len(bytes: &PyBytes, length: usize) -> PyResult<&PyBytes> {
    bytes.len().and_then(
        |actual_len| if actual_len == length { 
            Ok(bytes) 
        } else { 
            Err(exceptions::ValueError::py_err(format!("Expected bytes of length {}, got {}", length, actual_len)))
        })
}

fn _to_pytuple(any: &PyAny) -> PyResult<&PyTuple> {
    any.downcast::<PyTuple>()
        .map_err(|_| exceptions::TypeError::py_err("Expected tuple"))
}

// Main interface

#[pyfunction]
pub fn sign(keypair: Keypair, message: Message) -> PyResult<Sig> {
    let mut public = [0u8; 32];
    let mut private = [0u8; 64];
    public.clone_from_slice(&keypair.0[0..32]);
    private.clone_from_slice(&keypair.1[0..64]);
    let secret = match SecretKey::from_bytes(&private) {
        Ok(some_secret) => some_secret,
        Err(err) => return Err(exceptions::TypeError::py_err(format!("Invalid secret key: {}", err.to_string()))),
    };

    let public = match PublicKey::from_bytes(&public) {
        Ok(some_public) => some_public,
        Err(err) => return Err(exceptions::TypeError::py_err(format!("Invalid public key: {}", err.to_string()))),
    };

    let context = signing_context(SIGNING_CTX);
    let sig = secret.sign(context.bytes(&message.0), &public).to_bytes();
    Ok(Sig(sig))
}

#[pyfunction]
pub fn verify(signature: Sig, message: Message, pubkey: PubKey) -> bool {
    let sig = match Signature::from_bytes(&signature.0) {
        Ok(some_sig) => some_sig,
        Err(_) => return false,
    };
    let pk = match PublicKey::from_bytes(&pubkey.0) {
        Ok(some_pk) => some_pk,
        Err(_) => return false,
    };
    let result = pk.verify_simple(SIGNING_CTX, &message.0, &sig);
    result.is_ok()
}

#[pyfunction]
pub fn pair_from_seed(seed: Seed) -> PyResult<Keypair> {
    let k = MiniSecretKey::from_bytes(&seed.0).expect("32 bytes can always build a key; qed");
    let kp = k.expand_to_keypair(ExpansionMode::Ed25519);

    Ok(Keypair(kp.public.to_bytes(), kp.secret.to_bytes()))
}

/// Returns the soft derivation of the public key of the specified child.
///
/// # Arguments
///
/// * `extended_pubkey` - The extended public key, comprised of the chain code and public key.
/// * `index` - The identifier for the child key to derive.
#[pyfunction]
#[text_signature = "(extended_pubkey, index, /)"]
pub fn derive_pubkey(extended_pubkey: ExtendedPubKey, index: Message) -> PyResult<ExtendedPubKey> {
    let chain_code = ChainCode(extended_pubkey.0);
    let pubkey = PublicKey::from_bytes(&extended_pubkey.1)
        .map_err(|err| exceptions::TypeError::py_err(format!("Invalid public key: {}", err.to_string())))?;
    let (new_pubkey, new_chaincode) = pubkey.derived_key_simple(chain_code, &index.0);

    Ok(ExtendedPubKey(new_chaincode.0, new_pubkey.to_bytes()))
}

/// Returns the soft deriviation of the private and public key of the specified child.
///
/// # Arguments
///
/// * `extended_keypair` - The extended keypair, comprised of the chain code, public key, and private key.
/// * `index` - The identifier for the child key to derive.
#[pyfunction]
#[text_signature = "(extended_keypair, index, /)"]
pub fn derive_keypair(extended_keypair: ExtendedKeypair, index: Message) -> PyResult<ExtendedKeypair> {
    let chain_code = ChainCode(extended_keypair.0);
    let pubkey = PublicKey::from_bytes(&extended_keypair.1)
        .map_err(|err| exceptions::TypeError::py_err(format!("Invalid public key: {}", err.to_string())))?;
    let privkey = SecretKey::from_bytes(&extended_keypair.2)
        .map_err(|err| exceptions::TypeError::py_err(format!("Invalid secret key: {}", err.to_string())))?;
    let keypair = SchnorrkelKeypair{secret: privkey, public: pubkey};
    let (new_keypair, new_chaincode) = keypair.derived_key_simple(chain_code, &index.0);

    Ok(ExtendedKeypair(new_chaincode.0, new_keypair.public.to_bytes(), new_keypair.secret.to_bytes()))
}

// Convert Keypair object to a Python Keypair tuple
impl IntoPy<PyObject> for Keypair {
    fn into_py(self, py: Python) -> PyObject {
        let secret = PyBytes::new(py, &self.0);
        let public = PyBytes::new(py, &self.1);

        PyTuple::new(py, vec![secret, public]).into_py(py)
    }
}

// Convert Python Keypair into Rust
impl<'a> FromPyObject<'a> for Keypair {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let keypair = obj
            .downcast::<PyTuple>()
            .map_err(|_| exceptions::TypeError::py_err("Invalid Keypair: expected a tuple"))?;
        if keypair.len() < 2 {
            return Err(exceptions::IndexError::py_err(format!("Expected tuple of size 2, got {}", keypair.len())));
        }

        // Convert bytes to fixed width arrays
        let mut public: [u8; 32] = [0u8; 32];
        let mut private: [u8; 64] = [0u8; 64];
        public.clone_from_slice(
            &keypair.get_item(0)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Invalid PubKey: expected a python Bytes object"))?
                    .as_bytes()[0..32]);
        private.clone_from_slice(
            &keypair.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Invalid SecretKey: Expected a python Bytes object"))?
                    .as_bytes()[0..64]);
        let keypair = Keypair(public, private);
        Ok(keypair)
    }
}

// Convert Sig struct to a PyObject
impl IntoPy<PyObject> for Sig {
    fn into_py(self, py: Python) -> PyObject {
        let sig = PyBytes::new(py, &self.0);
        sig.into_py(py)
    }
}

// Convert a PyBytes object of size 64 to a Sig object
impl<'a> FromPyObject<'a> for Sig {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let signature = obj
            .downcast::<PyBytes>()
            .map_err(|_| exceptions::TypeError::py_err("Expected 64 byte signature"))
            .and_then(|b| _check_pybytes_len(b, 64))?;

        // Convert bytes to fixed width array
        let mut fixed: [u8; 64] = [0u8; 64];
        fixed.clone_from_slice(signature.as_bytes());
        Ok(Sig(fixed))
    }
}

// Convert a PyBytes object into a Seed
impl<'a> FromPyObject<'a> for Seed {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let seed = obj
            .downcast::<PyBytes>()
            .map_err(|_| PyErr::new::<exceptions::TypeError, _>("Expected a bytestring"))?;

        if seed.as_bytes().len() != 32 {
            return Err(PyErr::new::<exceptions::IndexError, _>(
                "Expected seed with length: 32",
            ));
        }

        // Convert bytes to fixed width array
        let mut fixed: [u8; 32] = Default::default();
        fixed.copy_from_slice(seed.as_bytes());
        Ok(Seed(fixed))
    }
}

// Convert a PyBytes object of size 32 to a PublicKey struct
impl<'a> FromPyObject<'a> for PubKey {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let pubkey = obj
            .downcast::<PyBytes>()
            .map_err(|_| exceptions::TypeError::py_err("Invalid PubKey, expected bytes object"))
            .and_then(|b| _check_pybytes_len(b, 32))?;
        
        // Convert bytes to fixed width array
        let mut fixed: [u8; 32] = Default::default();
        fixed.clone_from_slice(pubkey.as_bytes());
        Ok(PubKey(fixed))
    }
}

// Convert an arbitrary sized PyBytes object to a Message struct
impl<'a> FromPyObject<'a> for Message {
    fn extract(obj: &PyAny) -> PyResult<Self> {
        let messsge = obj
            .downcast::<PyBytes>()
            .map_err(|_| exceptions::TypeError::py_err("Expected bytes object"))?;
        Ok(Message(messsge.as_bytes().to_owned()))
    }
}

// Convert ExtendedPubKey into Python ExtendedPubKey tuple
impl IntoPy<PyObject> for ExtendedPubKey {
    fn into_py(self, py: Python) -> PyObject {
        let chain_code = PyBytes::new(py, &self.0);
        let public = PyBytes::new(py, &self.1);

        PyTuple::new(py, vec![chain_code, public]).into_py(py)
    }
}

// Convert Python ExtendedPubKey into Rust
impl<'a> FromPyObject<'a> for ExtendedPubKey {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let extended = _to_pytuple(obj)?;
        if extended.len() < 2 {
            return Err(exceptions::IndexError::py_err(format!("Expected tuple of size 2, got {}", extended.len())));
        }
        
        // Convert bytes to fixed width arrays
        let mut chain_code: [u8; CHAIN_CODE_LENGTH] = [0u8; CHAIN_CODE_LENGTH];
        let mut public: [u8; 32] = [0u8; 32];
        chain_code.clone_from_slice(
            &extended.get_item(0) 
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 0"))
                    .and_then(|b| _check_pybytes_len(b, 32))?
                    .as_bytes()[0..32]);
        public.clone_from_slice(
            &extended.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 1"))
                    .and_then(|b| _check_pybytes_len(b, 32))?
                    .as_bytes()[0..32]);
        let extended_pubkey = ExtendedPubKey(chain_code, public);
        Ok(extended_pubkey)
    }
}

// Convert ExtendedKeypair into Python ExtendedKeypair tuple
impl IntoPy<PyObject> for ExtendedKeypair {
    fn into_py(self, py: Python) -> PyObject {
        let chain_code = PyBytes::new(py, &self.0);
        let public = PyBytes::new(py, &self.1);
        let private = PyBytes::new(py, &self.2);

        PyTuple::new(py, vec![chain_code, public, private]).into_py(py)
    }
}

// Convert Python ExtendedKeypair into Rust
impl<'a> FromPyObject<'a> for ExtendedKeypair {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let extended = _to_pytuple(obj)?;
        if extended.len() < 3 {
            return Err(exceptions::IndexError::py_err(format!("Expected tuple of size 3, got {}", extended.len())));
        }
        
        // Convert bytes to fixed width arrays
        let mut chain_code: [u8; CHAIN_CODE_LENGTH] = [0u8; CHAIN_CODE_LENGTH];
        let mut public: [u8; 32] = [0u8; 32];
        let mut private: [u8; 64] = [0u8; 64];

        chain_code.clone_from_slice(
            &extended.get_item(0) 
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 0"))
                    .and_then(|b| _check_pybytes_len(b, 32))?
                    .as_bytes()[0..32]);
        public.clone_from_slice(
            &extended.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 1"))
                    .and_then(|b| _check_pybytes_len(b, 32))?
                    .as_bytes()[0..32]);
        private.clone_from_slice(
           &extended.get_item(2)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 2"))
                    .and_then(|b| _check_pybytes_len(b, 64))?
                    .as_bytes()[0..64]);
        let extended_keypair = ExtendedKeypair(chain_code, public, private);
        Ok(extended_keypair)
    }
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn sr25519(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(pair_from_seed))?;
    m.add_wrapped(wrap_pyfunction!(sign))?;
    m.add_wrapped(wrap_pyfunction!(verify))?;
    m.add_wrapped(wrap_pyfunction!(derive_pubkey))?;
    m.add_wrapped(wrap_pyfunction!(derive_keypair))?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SEED: [u8; 32] = [243u8, 14u8, 181u8, 138u8, 217u8, 189u8, 228u8, 167u8, 2u8, 218u8, 60u8, 114u8, 55u8, 9u8, 203u8, 250u8, 247u8, 3u8, 11u8, 34u8, 213u8, 228u8, 209u8, 107u8, 203u8, 247u8, 51u8, 201u8, 192u8, 155u8, 246u8, 189u8];
    static TEST_CHAIN_CODE: [u8; 32] = [121u8, 247u8, 8u8, 96u8, 40u8, 121u8, 203u8, 92u8, 236u8, 255u8, 245u8, 111u8, 87u8, 168u8, 85u8, 31u8, 241u8, 112u8, 2u8, 93u8, 119u8, 164u8, 45u8, 5u8, 58u8, 156u8, 175u8, 122u8, 196u8, 197u8, 67u8, 181u8];

    static TEST_PUBKEY: [u8; 32] = [14u8, 86u8, 60u8, 125u8, 203u8, 68u8, 70u8, 192u8, 237u8, 126u8, 122u8, 157u8, 159u8, 10u8, 58u8, 61u8, 65u8, 200u8, 118u8, 122u8, 135u8, 242u8, 5u8, 189u8, 72u8, 251u8, 142u8, 245u8, 219u8, 6u8, 107u8, 107u8];
    static TEST_PRIVKEY: [u8; 64] = [26u8, 71u8, 15u8, 91u8, 104u8, 90u8, 148u8, 63u8, 201u8, 13u8, 140u8, 14u8, 192u8, 205u8, 219u8, 74u8, 206u8, 40u8, 226u8, 111u8, 211u8, 224u8, 9u8, 30u8, 179u8, 154u8, 67u8, 51u8, 39u8, 125u8, 239u8, 11u8, 197u8, 203u8, 68u8, 206u8, 97u8, 51u8, 137u8, 104u8, 176u8, 213u8, 242u8, 2u8, 35u8, 70u8, 104u8, 74u8, 144u8, 186u8, 142u8, 82u8, 109u8, 217u8, 209u8, 192u8, 97u8, 111u8, 30u8, 118u8, 190u8, 94u8, 220u8, 255u8];

    static CHILD_CHAIN_CODE: [u8; 32] = [108u8, 98u8, 59u8, 119u8, 26u8, 182u8, 128u8, 8u8, 228u8, 211u8, 199u8, 57u8, 171u8, 245u8, 174u8, 50u8, 42u8, 43u8, 228u8, 78u8, 43u8, 212u8, 119u8, 227u8, 222u8, 194u8, 55u8, 160u8, 254u8, 94u8, 222u8, 30u8];
    static CHILD_PUBKEY: [u8; 32] = [94u8, 87u8, 139u8, 128u8, 5u8, 32u8, 18u8, 141u8, 227u8, 5u8, 110u8, 89u8, 226u8, 225u8, 26u8, 173u8, 37u8, 13u8, 215u8, 42u8, 40u8, 221u8, 223u8, 88u8, 134u8, 171u8, 127u8, 120u8, 8u8, 247u8, 100u8, 47u8];
    static CHILD_PRIVKEY: [u8; 64] = [79u8, 13u8, 181u8, 43u8, 93u8, 65u8, 5u8, 48u8, 58u8, 160u8, 239u8, 5u8, 43u8, 51u8, 4u8, 7u8, 39u8, 197u8, 253u8, 91u8, 238u8, 176u8, 167u8, 202u8, 18u8, 205u8, 130u8, 68u8, 237u8, 28u8, 101u8, 5u8, 241u8, 125u8, 35u8, 171u8, 110u8, 34u8, 104u8, 95u8, 3u8, 174u8, 194u8, 158u8, 183u8, 114u8, 43u8, 83u8, 183u8, 199u8, 148u8, 52u8, 236u8, 111u8, 56u8, 9u8, 86u8, 187u8, 144u8, 78u8, 204u8, 198u8, 221u8, 20u8];

    static TEST_MESSAGE: [u8; 9] = [1u8, 2u8, 3u8, 4u8, 5u8, 4u8, 3u8, 2u8, 1u8];

    #[test]
    fn test_pair_from_seed() -> PyResult<()> {
        let seed = Seed(TEST_SEED);
        let keypair = pair_from_seed(seed)?;

        assert_eq!(keypair.0, TEST_PUBKEY);
        assert_eq!(&keypair.1[0..64], &TEST_PRIVKEY[0..64]);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify() -> PyResult<()> {
        let signer_keypair = Keypair(TEST_PUBKEY, TEST_PRIVKEY);
        let signer_pubkey = PubKey(TEST_PUBKEY);

        let test_message = Message(Vec::from(TEST_MESSAGE));
        let test_message_copy = Message(Vec::from(TEST_MESSAGE));

        let signature = sign(signer_keypair, test_message)?;
        assert!(verify(signature, test_message_copy, signer_pubkey));
        Ok(())
    }

    #[test]
    fn test_derive_pubkey() -> PyResult<()> {
        let extended_pubkey = ExtendedPubKey(TEST_CHAIN_CODE, TEST_PUBKEY);
        let test_index = Message(vec![1u8, 2u8, 3u8, 4u8]);

        let child_ext_pubkey = derive_pubkey(extended_pubkey, test_index)?;
        assert_eq!(child_ext_pubkey.0, CHILD_CHAIN_CODE);
        assert_eq!(child_ext_pubkey.1, CHILD_PUBKEY);
        Ok(())
    }

    #[test]
    fn test_derive_keypair() -> PyResult<()> {
        let extended_keypair = ExtendedKeypair(TEST_CHAIN_CODE, TEST_PUBKEY, TEST_PRIVKEY);
        let test_index = Message(vec![1u8, 2u8, 3u8, 4u8]);

        let child_ext_keypair = derive_keypair(extended_keypair, test_index)?;
        assert_eq!(child_ext_keypair.0, CHILD_CHAIN_CODE);
        assert_eq!(child_ext_keypair.1, CHILD_PUBKEY);
        // The nonce is randomly generated each time, so just check the scalars are the same
        assert_eq!(&child_ext_keypair.2[0..32], &CHILD_PRIVKEY[0..32]);
        Ok(())
    }
}