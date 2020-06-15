
//! Python bindings for the schnorrkel library.
//!
//! py-sr25519-bindings provides bindings to the Rust create
//! [schnorrkel](https://crates.io/crates/schnorrkel), allowing for some limited
//! use and management of sr25519 elliptic keys.

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyTuple};
use pyo3::{wrap_pyfunction, FromPyObject, IntoPy, PyObject};
use schnorrkel::context::signing_context;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey, PublicKey, SecretKey, Keypair as SchnorrkelKeypair};
use schnorrkel::sign::Signature;
use schnorrkel::derive::{Derivation, ChainCode};

pub use schnorrkel::keys::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, MINI_SECRET_KEY_LENGTH};
pub use schnorrkel::sign::SIGNATURE_LENGTH;
pub use schnorrkel::derive::CHAIN_CODE_LENGTH;

const SIGNING_CTX: &'static [u8] = b"substrate";

pub struct Seed([u8; MINI_SECRET_KEY_LENGTH]);
pub struct Keypair([u8; PUBLIC_KEY_LENGTH], [u8; SECRET_KEY_LENGTH]);
pub struct PubKey([u8; PUBLIC_KEY_LENGTH]);
pub struct PrivKey([u8; SECRET_KEY_LENGTH]);
pub struct Sig([u8; SIGNATURE_LENGTH]);
pub struct Message(Vec<u8>);
pub struct ExtendedPubKey([u8; CHAIN_CODE_LENGTH], [u8; PUBLIC_KEY_LENGTH]);
pub struct ExtendedKeypair([u8; CHAIN_CODE_LENGTH], [u8; PUBLIC_KEY_LENGTH], [u8; SECRET_KEY_LENGTH]);


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
#[text_signature = "(keypair, message)"]
pub fn sign(keypair: Keypair, message: Message) -> PyResult<Sig> {
    let mut public = [0u8; PUBLIC_KEY_LENGTH];
    let mut private = [0u8; SECRET_KEY_LENGTH];
    public.clone_from_slice(&keypair.0[0..PUBLIC_KEY_LENGTH]);
    private.clone_from_slice(&keypair.1[0..SECRET_KEY_LENGTH]);
    let secret = match SecretKey::from_bytes(&private) {
        Ok(some_secret) => some_secret,
        Err(err) => return Err(exceptions::ValueError::py_err(format!("Invalid secret key: {}", err.to_string()))),
    };

    let public = match PublicKey::from_bytes(&public) {
        Ok(some_public) => some_public,
        Err(err) => return Err(exceptions::ValueError::py_err(format!("Invalid public key: {}", err.to_string()))),
    };

    let context = signing_context(SIGNING_CTX);
    let sig = secret.sign(context.bytes(&message.0), &public).to_bytes();
    Ok(Sig(sig))
}

#[pyfunction]
#[text_signature = "(signature, message, pubkey)"]
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

/// Returns a public and private key pair from the given 32-byte seed.
///
/// # Arguments
/// 
/// * `seed` - A 32 byte seed.
///
/// # Returns
///
/// A tuple containing the 32-byte public key and 64-byte secret key, in that order.
#[pyfunction]
#[text_signature = "(seed)"]
pub fn pair_from_seed(seed: Seed) -> PyResult<Keypair> {
    let k = MiniSecretKey::from_bytes(&seed.0).expect("32 bytes can always build a key; qed");
    let kp = k.expand_to_keypair(ExpansionMode::Ed25519);

    Ok(Keypair(kp.public.to_bytes(), kp.secret.to_bytes()))
}

/// Returns the corresponding public key for the given secret key.
///
/// # Arguments
///
/// * `secret_key` - The sr25519 secret key, comprised of the 32 byte scalar and 32 byte nonce.
///
/// # Returns
///
/// The 32-byte public key corresponding to the provided secret key.
///
/// # Raises
///
/// * `ValueError` - If the provided secret key is invalid.
#[pyfunction]
#[text_signature = "(secret_key)"]
pub fn public_from_secret_key(secret_key: PrivKey) -> PyResult<PubKey> {
    let sec_key = match SecretKey::from_bytes(&secret_key.0) {
        Ok(some_key) => some_key,
        Err(err) => return Err(exceptions::ValueError::py_err(format!("Invalid secret key: {}", err.to_string()))),
    };
    let pub_key = sec_key.to_public();

    Ok(PubKey(pub_key.to_bytes()))
}


/// Returns the soft derivation of the public key of the specified child.
///
/// # Arguments
///
/// * `extended_pubkey` - The extended public key, comprised of the chain code and public key.
/// * `id` - The identifier for the child key to derive.
///
/// # Returns
///
/// A new extended public key for the child.
#[pyfunction]
#[text_signature = "(extended_pubkey, id)"]
pub fn derive_pubkey(extended_pubkey: ExtendedPubKey, id: Message) -> PyResult<ExtendedPubKey> {
    let chain_code = ChainCode(extended_pubkey.0);
    let pubkey = PublicKey::from_bytes(&extended_pubkey.1)
        .map_err(|err| exceptions::ValueError::py_err(format!("Invalid public key: {}", err.to_string())))?;
    let (new_pubkey, new_chaincode) = pubkey.derived_key_simple(chain_code, &id.0);

    Ok(ExtendedPubKey(new_chaincode.0, new_pubkey.to_bytes()))
}

/// Returns the soft deriviation of the private and public key of the specified child.
///
/// # Arguments
///
/// * `extended_keypair` - The extended keypair, comprised of the chain code, public key, and private key.
/// * `id` - The identifier for the child key to derive.
///
/// # Returns
///
/// A new extended keypair for the child.
///
/// *NOTE:* The chain code, public key, and secret key scalar are generated
/// deterministically, but the secret key nonce is *RANDOM*, even with
/// identical input.
#[pyfunction]
#[text_signature = "(extended_keypair, id)"]
pub fn derive_keypair(extended_keypair: ExtendedKeypair, id: Message) -> PyResult<ExtendedKeypair> {
    let chain_code = ChainCode(extended_keypair.0);
    let pubkey = PublicKey::from_bytes(&extended_keypair.1)
        .map_err(|err| exceptions::ValueError::py_err(format!("Invalid public key: {}", err.to_string())))?;
    let privkey = SecretKey::from_bytes(&extended_keypair.2)
        .map_err(|err| exceptions::ValueError::py_err(format!("Invalid secret key: {}", err.to_string())))?;
    let keypair = SchnorrkelKeypair{secret: privkey, public: pubkey};
    let (new_keypair, new_chaincode) = keypair.derived_key_simple(chain_code, &id.0);

    Ok(ExtendedKeypair(new_chaincode.0, new_keypair.public.to_bytes(), new_keypair.secret.to_bytes()))
}

/// Returns the hard derivation of the private and public key of the specified child.
///
/// This derivation is performed using the secret material for the key, so even knowing
/// the extended public key of this or a child key is not enough to go any further up the
/// hierarchy.
///
/// # Arguments
///
/// * `extended_keypair` - The extended keypair, comprised of the chain code, public key, and private key.
/// * `id` - The identifier for the child key to derive.
///
/// # Returns
///
/// A new extended keypair for the child.
///
/// *NOTE:* The chain code, public key, and secret key scalar are generated
/// deterministically, but the secret key nonce is *RANDOM*, even with
/// identical input.
#[pyfunction]
#[text_signature = "(extended_keypair, id)"]
pub fn hard_derive_keypair(extended_keypair: ExtendedKeypair, id: Message) -> PyResult<ExtendedKeypair> {
    let chain_code = ChainCode(extended_keypair.0);
    let privkey = SecretKey::from_bytes(&extended_keypair.2)
        .map_err(|err| exceptions::ValueError::py_err(format!("Invalid secret key: {}", err.to_string())))?;

    let (new_mini, new_chaincode) = privkey.hard_derive_mini_secret_key(Some(chain_code), &id.0);
    let new_keypair = new_mini.expand_to_keypair(ExpansionMode::Ed25519);
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
        let mut public: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        let mut private: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];
        public.clone_from_slice(
            &keypair.get_item(0)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Invalid PubKey: expected a python Bytes object"))
                    .and_then(|b| _check_pybytes_len(b, PUBLIC_KEY_LENGTH))?
                    .as_bytes()[0..PUBLIC_KEY_LENGTH]);
        private.clone_from_slice(
            &keypair.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Invalid SecretKey: Expected a python Bytes object"))
                    .and_then(|b| _check_pybytes_len(b, SECRET_KEY_LENGTH))?
                    .as_bytes()[0..SECRET_KEY_LENGTH]);
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
            .map_err(|_| exceptions::TypeError::py_err(format!("Expected {} byte signature", SIGNATURE_LENGTH)))
            .and_then(|b| _check_pybytes_len(b, SIGNATURE_LENGTH))?;

        // Convert bytes to fixed width array
        let mut fixed: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
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

        if seed.as_bytes().len() != MINI_SECRET_KEY_LENGTH {
            return Err(PyErr::new::<exceptions::IndexError, _>(
                format!("Expected seed with length: {}", MINI_SECRET_KEY_LENGTH),
            ));
        }

        // Convert bytes to fixed width array
        let mut fixed: [u8; MINI_SECRET_KEY_LENGTH] = Default::default();
        fixed.copy_from_slice(seed.as_bytes());
        Ok(Seed(fixed))
    }
}

// Convert PubKey struct to a PyObject
impl IntoPy<PyObject> for PubKey {
    fn into_py(self, py: Python) -> PyObject {
        let key = PyBytes::new(py, &self.0);
        key.into_py(py)
    }
}

// Convert a PyBytes object of size 32 to a PublicKey struct
impl<'a> FromPyObject<'a> for PubKey {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let pubkey = obj
            .downcast::<PyBytes>()
            .map_err(|_| exceptions::TypeError::py_err("Invalid PubKey, expected bytes object"))
            .and_then(|b| _check_pybytes_len(b, PUBLIC_KEY_LENGTH))?;
        
        // Convert bytes to fixed width array
        let mut fixed: [u8; PUBLIC_KEY_LENGTH] = Default::default();
        fixed.clone_from_slice(pubkey.as_bytes());
        Ok(PubKey(fixed))
    }
}

// Convert PrivKey struct to a PyObject
impl IntoPy<PyObject> for PrivKey {
    fn into_py(self, py: Python) -> PyObject {
        let key = PyBytes::new(py, &self.0);
        key.into_py(py)
    }
}

// Convert a PyBytes object of size 64 to a PrivKey object
impl<'a> FromPyObject<'a> for PrivKey {
    fn extract(obj: &'a PyAny) -> PyResult<Self> {
        let secret = obj
            .downcast::<PyBytes>()
            .map_err(|_| exceptions::TypeError::py_err(format!("Expected {} byte secret key", SECRET_KEY_LENGTH)))
            .and_then(|b| _check_pybytes_len(b, SECRET_KEY_LENGTH))?;

        // Convert bytes to fixed width array
        let mut fixed: [u8; 64] = [0u8; SECRET_KEY_LENGTH];
        fixed.clone_from_slice(secret.as_bytes());
        Ok(PrivKey(fixed))
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
        // Don't check that the length matches exactly here so that an extended
        // private key can be passed in as well.
        if extended.len() < 2 {
            return Err(exceptions::IndexError::py_err(format!("Expected tuple of size 2, got {}", extended.len())));
        }
        
        // Convert bytes to fixed width arrays
        let mut chain_code: [u8; CHAIN_CODE_LENGTH] = [0u8; CHAIN_CODE_LENGTH];
        let mut public: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        chain_code.clone_from_slice(
            &extended.get_item(0) 
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 0"))
                    .and_then(|b| _check_pybytes_len(b, CHAIN_CODE_LENGTH))?
                    .as_bytes()[0..CHAIN_CODE_LENGTH]);
        public.clone_from_slice(
            &extended.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 1"))
                    .and_then(|b| _check_pybytes_len(b, PUBLIC_KEY_LENGTH))?
                    .as_bytes()[0..PUBLIC_KEY_LENGTH]);
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
        let mut public: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        let mut private: [u8; SECRET_KEY_LENGTH] = [0u8; SECRET_KEY_LENGTH];

        chain_code.clone_from_slice(
            &extended.get_item(0) 
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 0"))
                    .and_then(|b| _check_pybytes_len(b, CHAIN_CODE_LENGTH))?
                    .as_bytes()[0..CHAIN_CODE_LENGTH]);
        public.clone_from_slice(
            &extended.get_item(1)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 1"))
                    .and_then(|b| _check_pybytes_len(b, PUBLIC_KEY_LENGTH))?
                    .as_bytes()[0..PUBLIC_KEY_LENGTH]);
        private.clone_from_slice(
           &extended.get_item(2)
                    .downcast::<PyBytes>()
                    .map_err(|_| exceptions::TypeError::py_err("Expected bytes object at index 2"))
                    .and_then(|b| _check_pybytes_len(b, SECRET_KEY_LENGTH))?
                    .as_bytes()[0..SECRET_KEY_LENGTH]);
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
    m.add_wrapped(wrap_pyfunction!(public_from_secret_key))?;
    m.add_wrapped(wrap_pyfunction!(derive_pubkey))?;
    m.add_wrapped(wrap_pyfunction!(derive_keypair))?;
    m.add_wrapped(wrap_pyfunction!(hard_derive_keypair))?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    static TEST_SEED: [u8; MINI_SECRET_KEY_LENGTH] = hex!("f30eb58ad9bde4a702da3c723709cbfaf7030b22d5e4d16bcbf733c9c09bf6bd");
    static TEST_CHAIN_CODE: [u8; CHAIN_CODE_LENGTH] = hex!("79f708602879cb5cecfff56f57a8551ff170025d77a42d053a9caf7ac4c543b5");

    static TEST_PUBKEY: [u8; PUBLIC_KEY_LENGTH] = hex!("0e563c7dcb4446c0ed7e7a9d9f0a3a3d41c8767a87f205bd48fb8ef5db066b6b");
    static TEST_PRIVKEY: [u8; SECRET_KEY_LENGTH] = hex!("1a470f5b685a943fc90d8c0ec0cddb4ace28e26fd3e0091eb39a4333277def0bc5cb44ce61338968b0d5f2022346684a90ba8e526dd9d1c0616f1e76be5edcff");

    static CHILD_CHAIN_CODE: [u8; CHAIN_CODE_LENGTH] = hex!("6c623b771ab68008e4d3c739abf5ae322a2be44e2bd477e3dec237a0fe5ede1e");
    static CHILD_PUBKEY: [u8; PUBLIC_KEY_LENGTH] = hex!("5e578b800520128de3056e59e2e11aad250dd72a28dddf5886ab7f7808f7642f");
    static CHILD_PRIVKEY: [u8; SECRET_KEY_LENGTH] = hex!("4f0db52b5d4105303aa0ef052b33040727c5fd5beeb0a7ca12cd8244ed1c6505f17d23ab6e22685f03aec29eb7722b53b7c79434ec6f380956bb904eccc6dd14");

    static CHILD_CHAIN_CODE_HARD: [u8; CHAIN_CODE_LENGTH] = hex!("0e89c4b7b29d92138c0a093b9f9cf9a0132960f52664a188e6d0e3ef324316cc");
    static CHILD_PUBKEY_HARD: [u8; PUBLIC_KEY_LENGTH] = hex!("8c0ff65769fdb4bfdf12e628261f39bfb29fba94353b6faddbcddcd455d4ea29");
    static CHILD_PRIVKEY_HARD: [u8; SECRET_KEY_LENGTH] = hex!("1c76b89abb8cce5310fa40ef7f197b6c0fd482f2b59e1a524ec30736fbcf580881f2e63b515c6be0a484e3ceaefce0372f1826d3dd230502f8cea22a323bfbb1");

    static TEST_MESSAGE: &[u8] =
        b"All of the world's a stage \
        And all the men and women merely players; \
        They have their exits and their entrances, \
        And one man in his time plays many parts, \
        His acts being seven ages.";

    #[test]
    fn test_pair_from_seed() -> PyResult<()> {
        let seed = Seed(TEST_SEED);
        let keypair = pair_from_seed(seed)?;

        assert_eq!(keypair.0, TEST_PUBKEY);
        assert_eq!(&keypair.1[0..SECRET_KEY_LENGTH], &TEST_PRIVKEY[0..SECRET_KEY_LENGTH]);
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
    fn test_public_from_secret_key() -> PyResult<()> {
        let secret = PrivKey(TEST_PRIVKEY);

        let pubkey = public_from_secret_key(secret)?;
        assert_eq!(pubkey.0, TEST_PUBKEY);
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
        assert_eq!(&child_ext_keypair.2[0..PUBLIC_KEY_LENGTH], &CHILD_PRIVKEY[0..PUBLIC_KEY_LENGTH]);
        Ok(())
    }

    #[test]
    fn test_hard_derive_keypair() -> PyResult<()> {
        let extended_keypair = ExtendedKeypair(TEST_CHAIN_CODE, TEST_PUBKEY, TEST_PRIVKEY);
        let test_index = Message(vec![1u8, 2u8, 3u8, 4u8]);

        let child_ext_keypair = hard_derive_keypair(extended_keypair, test_index)?;
        assert_eq!(child_ext_keypair.0, CHILD_CHAIN_CODE_HARD);
        assert_eq!(child_ext_keypair.1, CHILD_PUBKEY_HARD);
        // The nonce is randomly generated each time, so just check the scalars are the same
        assert_eq!(&child_ext_keypair.2[0..PUBLIC_KEY_LENGTH], &CHILD_PRIVKEY_HARD[0..PUBLIC_KEY_LENGTH]);
        Ok(())
    }
}