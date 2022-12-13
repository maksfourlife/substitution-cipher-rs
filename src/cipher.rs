use derive_more::Display;
use std::{collections::HashMap, hash::Hash};

pub trait Cipher {
    type Error;
    fn encrypt(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error>;
    fn decrypt(&self, cipher_text: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error>;
}

fn inverse_map<K, V>(m: HashMap<K, V>) -> HashMap<V, K>
where
    V: Eq + Hash,
{
    let mut result = HashMap::with_capacity(m.capacity());
    for (k, v) in m {
        result.insert(v, k);
    }
    result
}

fn substitue(
    map: &HashMap<u8, u8>,
    data: impl AsRef<[u8]>,
) -> Result<Vec<u8>, SubstitutionCipherError> {
    data.as_ref()
        .iter()
        .map(|k| {
            map.get(k)
                .copied()
                .ok_or(SubstitutionCipherError::UnknwonCharacter)
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct SubstitutionCipher {
    map: HashMap<u8, u8>,
    inverse_map: HashMap<u8, u8>,
}

#[derive(Debug, Display)]
pub enum SubstitutionCipherError {
    UnknwonCharacter,
    MapNotSymmetric,
}

impl SubstitutionCipher {
    pub fn new(map: HashMap<u8, u8>) -> Result<Self, SubstitutionCipherError> {
        let inverse_map = inverse_map(map.clone());
        if map.len() != inverse_map.len() {
            Err(SubstitutionCipherError::MapNotSymmetric)
        } else {
            Ok(Self { map, inverse_map })
        }
    }
}

impl Cipher for SubstitutionCipher {
    type Error = SubstitutionCipherError;

    fn encrypt(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        substitue(&self.map, message)
    }

    fn decrypt(&self, cipher_text: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        substitue(&self.inverse_map, cipher_text)
    }
}

#[cfg(test)]
mod test {
    use super::{Cipher, SubstitutionCipher};
    use std::collections::HashMap;

    #[test]
    fn test_substitution_symmetric() {
        let mut key = HashMap::new();
        key.insert(1, 2);
        key.insert(2, 3);
        key.insert(3, 1);
        let cipher = SubstitutionCipher::new(key).unwrap();
        let message = vec![1, 1, 2, 2, 3, 1, 1, 2, 3, 2, 3];
        let cipher_text = cipher.encrypt(&message).unwrap();
        let restored_message = cipher.decrypt(&cipher_text).unwrap();
        assert_eq!(message, restored_message);
    }
}
