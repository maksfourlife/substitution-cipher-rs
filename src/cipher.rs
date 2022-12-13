use derive_more::Display;
use num::{one, zero, Integer};
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
mod substitution_cipher_test {
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
        assert_ne!(message, cipher_text);
        assert_eq!(message, restored_message);
    }
}

#[derive(Debug, Display)]
pub enum AffineCipherError {
    #[display(fmt = "alphabet has repeating characters")]
    RepeatingAlphabet,
    #[display(fmt = "'a' and 'm' values are not coprime")]
    NotCoprime,
    #[display(fmt = "unknown character {}", _0)]
    UnknownCharacter(u8),
}

/// Affine cipher
/// https://en.wikipedia.org/wiki/Affine_cipher
#[derive(Debug, Clone)]
pub struct AffineCipher {
    /// maps characters to indices
    alph: HashMap<u8, usize>,
    /// maps indices to characters
    inverse_alph: HashMap<usize, u8>,
    /// modular multiplicative inverse of 'a' over 'm'
    inverse_a: usize,
    /// affine 'a' param
    a: usize,
    /// affine 'b' param
    b: usize,
}

fn get_alph_map(alph: impl IntoIterator<Item = u8>) -> HashMap<usize, u8> {
    alph.into_iter().enumerate().collect()
}

impl AffineCipher {
    pub fn new(alph: impl AsRef<[u8]>, a: usize, b: usize) -> Result<Self, AffineCipherError> {
        let inverse_alph = get_alph_map(alph.as_ref().iter().copied());
        let alph = inverse_map(inverse_alph.clone());
        if alph.len() != inverse_alph.len() {
            return Err(AffineCipherError::RepeatingAlphabet);
        }
        // https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
        let gcd = (a as i64).extended_gcd(&(alph.len() as i64));
        if gcd.gcd != one() {
            return Err(AffineCipherError::NotCoprime);
        }
        let mut inverse_a = gcd.x;
        if inverse_a < zero() {
            inverse_a += alph.len() as i64;
        }
        let inverse_a: usize = inverse_a.try_into().unwrap();
        Ok(Self {
            alph,
            inverse_alph,
            inverse_a,
            a,
            b,
        })
    }
}

impl Cipher for AffineCipher {
    type Error = AffineCipherError;

    fn encrypt(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        message
            .as_ref()
            .iter()
            .copied()
            .map(|ch| match self.alph.get(&ch) {
                Some(x) => {
                    let y = (self.a * x + self.b) % self.alph.len();
                    Ok(self.inverse_alph.get(&y).copied().unwrap())
                }
                _ => Err(AffineCipherError::UnknownCharacter(ch)),
            })
            .collect()
    }

    fn decrypt(&self, cipher_text: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        let m = self.alph.len();
        cipher_text
            .as_ref()
            .iter()
            .copied()
            .map(|ch| match self.alph.get(&ch) {
                Some(y) => {
                    // todo: either
                    //  - use i64
                    //  - substract with modulo
                    let x = (self.inverse_a * (m + y - self.b)) % m;
                    Ok(self.inverse_alph.get(&x).copied().unwrap())
                }
                _ => Err(AffineCipherError::UnknownCharacter(ch)),
            })
            .collect()
    }
}

#[cfg(test)]
mod affine_cipher_test {
    use super::{AffineCipher, Cipher};

    const ALPH: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,! ";

    #[test]
    fn test_affine_works() {
        let cipher = AffineCipher::new(ALPH, 376, 11).unwrap();
        let message = "Hello, world!";
        let cipher_text = cipher.encrypt(message).unwrap();
        let restored = cipher.decrypt(&cipher_text).unwrap();
        // println!("cipher_text: {}", String::from_utf8(cipher_text).unwrap());
        // println!("restored: {}", String::from_utf8(restored.clone()).unwrap());
        assert_ne!(message.as_bytes(), cipher_text); // sanity
        assert_eq!(message.as_bytes(), restored);
    }
}
