use derive_more::Display;
use num::{one, Integer, Signed};
use std::{
    collections::HashMap,
    hash::Hash,
    iter::{repeat_with, RepeatWith, Zip},
};

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

#[derive(Clone, Debug)]
struct Alphabet {
    direct: HashMap<u8, usize>,
    inverse: HashMap<usize, u8>,
}

impl Alphabet {
    /// Constructs alphabet. If 'a' has repeating characters, returns None
    pub fn new(a: impl AsRef<[u8]>) -> Option<Self> {
        let inverse: HashMap<_, _> = a.as_ref().iter().copied().enumerate().collect();
        let direct = inverse_map(inverse.clone());
        if inverse.len() != direct.len() {
            None
        } else {
            Some(Self { inverse, direct })
        }
    }

    pub fn len(&self) -> usize {
        self.direct.len()
    }

    pub fn get_index(&self, l: &u8) -> Option<usize> {
        self.direct.get(l).copied()
    }

    pub fn get_letter(&self, i: &usize) -> Option<u8> {
        self.inverse.get(i).copied()
    }
}

/// Common errors for both 'AffineCipher' and 'AffineRecurrentCipher'
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
    alph: Alphabet,
    /// modular multiplicative inverse of 'a' over 'm'
    inverse_a: usize,
    /// affine 'a' param
    a: usize,
    /// affine 'b' param
    b: usize,
}

/// Calculates modular multiplicative inverse for given integers.
/// Returns None if they are not coprime.
/// https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
#[inline]
fn modular_multiplicative_inverse<A: Integer + Signed + Copy>(a: A, m: A) -> Option<A> {
    let gcd = a.extended_gcd(&m);
    if gcd.gcd != one() {
        None
    } else {
        Some(gcd.x)
    }
}

#[inline]
fn absmod<A: Integer + Signed + Copy>(a: A, m: A) -> A {
    if a.is_negative() {
        let n = (a / m).abs() + one();
        (a + n * m) % m
    } else {
        a % m
    }
}

impl AffineCipher {
    pub fn new(alph: impl AsRef<[u8]>, a: usize, b: usize) -> Result<Self, AffineCipherError> {
        let alph = Alphabet::new(alph).ok_or(AffineCipherError::RepeatingAlphabet)?;
        let m = alph.len();
        let inverse_a = absmod(
            modular_multiplicative_inverse(a as i64, m as i64)
                .ok_or(AffineCipherError::NotCoprime)?,
            m as i64,
        ) as usize;
        Ok(Self {
            alph,
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
            .map(|ch| match self.alph.get_index(&ch) {
                Some(x) => {
                    let y = (self.a * x + self.b) % self.alph.len();
                    Ok(self.alph.get_letter(&y).unwrap())
                }
                _ => Err(AffineCipherError::UnknownCharacter(ch)),
            })
            .collect()
    }

    fn decrypt(&self, cipher_text: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        let m = self.alph.len();
        let inverse_b = absmod(-(self.b as i64), m as i64) as usize;
        cipher_text
            .as_ref()
            .iter()
            .copied()
            .map(|ch| match self.alph.get_index(&ch) {
                Some(y) => {
                    // y + inverse_b === y - b (mod m)
                    let x = (self.inverse_a * (y + inverse_b)) % m;
                    Ok(self.alph.get_letter(&x).unwrap())
                }
                _ => Err(AffineCipherError::UnknownCharacter(ch)),
            })
            .collect()
    }
}

#[cfg(test)]
const ALPH: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,! ";

#[cfg(test)]
mod affine_cipher_test {
    use super::{absmod, AffineCipher, Cipher};
    use crate::cipher::ALPH;

    #[test]
    fn test_absmod() {
        assert_eq!(absmod(-2, 7), 5);
        assert_eq!(absmod(-9, 7), 5);
        assert_eq!(absmod(-51, 7), 5);
    }

    #[test]
    fn test_affine_works() {
        let cipher = AffineCipher::new(ALPH, 376, 111).unwrap();
        let message = "Hello, world!";
        let cipher_text = cipher.encrypt(message).unwrap();
        let restored = cipher.decrypt(&cipher_text).unwrap();
        // println!("cipher_text: {}", String::from_utf8(cipher_text).unwrap());
        // println!("restored: {}", String::from_utf8(restored.clone()).unwrap());
        assert_ne!(message.as_bytes(), cipher_text); // sanity
        assert_eq!(message.as_bytes(), restored);
    }
}

#[derive(Clone, Debug)]
pub struct AffineRecurrentCipher {
    alph: Alphabet,
    a1: usize,
    a2: usize,
    b1: usize,
    b2: usize,
}

impl AffineRecurrentCipher {
    pub fn new(
        alph: impl AsRef<[u8]>,
        a1: usize,
        a2: usize,
        b1: usize,
        b2: usize,
    ) -> Result<Self, AffineCipherError> {
        let alph = Alphabet::new(alph).ok_or(AffineCipherError::RepeatingAlphabet)?;
        Ok(Self {
            alph,
            a1,
            a2,
            b1,
            b2,
        })
    }

    pub fn iter_a(&self) -> RepeatWith<impl FnMut() -> usize> {
        let m = self.alph.len();
        let mut a1 = self.a1;
        let mut a2 = self.a2;
        let mut i = 0;
        repeat_with(move || {
            let x = match i {
                0 => a1,
                1 => a2,
                _ => {
                    let tmp = (a1 * a2) % m;
                    a1 = std::mem::replace(&mut a2, tmp);
                    a2
                }
            };
            i += 1;
            x
        })
    }

    pub fn iter_b(&self) -> RepeatWith<impl FnMut() -> usize> {
        let m = self.alph.len();
        let mut b1 = self.b1;
        let mut b2 = self.b2;
        let mut i = 0;
        repeat_with(move || {
            let x = match i {
                0 => b1,
                1 => b2,
                _ => {
                    let tmp = (b1 + b2) % m;
                    b1 = std::mem::replace(&mut b2, tmp);
                    b2
                }
            };
            i += 1;
            x
        })
    }

    fn iter_keys(
        &self,
    ) -> Zip<RepeatWith<impl FnMut() -> usize>, RepeatWith<impl FnMut() -> usize>> {
        self.iter_a().zip(self.iter_b())
    }
}

impl Cipher for AffineRecurrentCipher {
    type Error = AffineCipherError;

    fn encrypt(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, Self::Error> {
        message
            .as_ref()
            .iter()
            .copied()
            .zip(self.iter_keys())
            .map(|(ch, (a, b))| match self.alph.get_index(&ch) {
                Some(x) => {
                    let y = (a * x + b) % self.alph.len();
                    Ok(self.alph.get_letter(&y).unwrap())
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
            .zip(self.iter_keys())
            .map(|(ch, (a, b))| match self.alph.get_index(&ch) {
                Some(y) => {
                    let inverse_a = absmod(
                        modular_multiplicative_inverse(a as i64, m as i64)
                            .ok_or(AffineCipherError::NotCoprime)?,
                        m as i64,
                    ) as usize;
                    let inverse_b = absmod(-(b as i64), m as i64) as usize;
                    let x = (inverse_a * (y + inverse_b)) % m;
                    Ok(self.alph.get_letter(&x).unwrap())
                }
                _ => Err(AffineCipherError::UnknownCharacter(ch)),
            })
            .collect()
    }
}

#[cfg(test)]
mod affine_recurrent_cipher_test {
    use super::{AffineRecurrentCipher, Cipher, ALPH};

    #[test]
    fn test_iter_keys() {
        let cipher = AffineRecurrentCipher::new(ALPH, 356, 357, 111, 112).unwrap();
        let mut it = cipher.iter_keys();
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
        println!("{:?}", it.next());
    }

    #[test]
    fn test_symmetric() {
        let cipher = AffineRecurrentCipher::new(ALPH, 356, 357, 111, 112).unwrap();
        let msg = "Hello, world!";
        let cipher_text = cipher.encrypt(&msg).unwrap();
        let restored = cipher.decrypt(&cipher_text).unwrap();
        // println!("cipher_text: {:?}", String::from_utf8(cipher_text.clone()));
        // println!("restored: {:?}", String::from_utf8(restored.clone()));
        assert_eq!(msg.as_bytes(), restored);
    }
}
