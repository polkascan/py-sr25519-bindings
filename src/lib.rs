use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyTuple};
use pyo3::{wrap_pyfunction, FromPyObject, IntoPy, PyObject};
use schnorrkel::context::signing_context;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey, PublicKey, SecretKey};
use schnorrkel::sign::{Signature};

const SIGNING_CTX: &'static [u8] = b"substrate";

pub struct Seed([u8; 32]);
pub struct Keypair([u8; 32], [u8; 64]);
pub struct PubKey([u8; 32]);
pub struct Sig([u8; 64]);
pub struct Message(Vec<u8>);


#[pyfunction]
pub fn sign(keypair: Keypair, message: Message) -> PyResult<Sig> {
    let mut public = [0u8; 32];
    let mut private = [0u8; 64];
    public.clone_from_slice(&keypair.0[0..32]);
    private.clone_from_slice(&keypair.1[0..64]);
    let secret = match SecretKey::from_bytes(&private) {
        Ok(some_secret) => some_secret,
        Err(_) => panic!("Provided private key is invalid."),
    };

    let public = match PublicKey::from_bytes(&public) {
        Ok(some_public) => some_public,
        Err(_) => panic!("Provided public key is invalid."),
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
            .expect("Expected a tuple");

        // Convert bytes to fixed width arrays
        let mut public: [u8; 32] = [0u8; 32];
        let mut private: [u8; 64] = [0u8; 64];
        public.clone_from_slice(
            &keypair.get_item(0)
                    .downcast::<PyBytes>()
                    .expect("Expected a python Bytes object")
                    .as_bytes()[0..32]);
        private.clone_from_slice(
            &keypair.get_item(1)
                    .downcast::<PyBytes>()
                    .expect("Expected a python Bytes object")
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
            .expect("Expected 64 byte signature");

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
            .expect("Expected 32 byte seed");

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
            .expect("Expected param to be an array of bytes");
        Ok(Message(messsge.as_bytes().to_owned()))
    }
}


/// This module is a python module implemented in Rust.
#[pymodule]
fn sr25519(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(pair_from_seed))?;
    m.add_wrapped(wrap_pyfunction!(sign))?;
    m.add_wrapped(wrap_pyfunction!(verify))?;

    Ok(())
}
