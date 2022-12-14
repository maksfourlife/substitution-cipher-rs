use derive_more::Display;
use num::{one, Integer, Signed};
use std::{
    collections::HashMap,
    hash::Hash,
    iter::{repeat_with, RepeatWith, Zip},
};

/// Common errors for ciphers
#[derive(Debug, Display)]
pub enum CipherError {
    #[display(fmt = "alphabet has repeating characters")]
    RepeatingAlphabet,
    #[display(fmt = "alphabets are not symmetric")]
    NonSymmetricAlphabets,
    #[display(fmt = "'a' and 'm' values are not coprime")]
    NotCoprime,
    #[display(fmt = "unknown character {}", _0)]
    UnknownCharacter(u8),
}

impl std::error::Error for CipherError {}

pub trait Cipher {
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CipherError>;
    fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CipherError>;
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
    alph1: &Alphabet,
    alph2: &Alphabet,
    data: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    data.as_ref()
        .iter()
        .map(|k| {
            Ok(alph1
                .get_letter(
                    &alph2
                        .get_index(k)
                        .ok_or(CipherError::UnknownCharacter(*k))?,
                )
                .expect("alph1 != alph2^-1"))
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct SubstitutionCipher {
    alph1: Alphabet,
    alph2: Alphabet,
}

impl SubstitutionCipher {
    pub fn new(alph1: impl AsRef<[u8]>, alph2: impl AsRef<[u8]>) -> Result<Self, CipherError> {
        let alph1 = Alphabet::new(alph1).ok_or(CipherError::RepeatingAlphabet)?;
        let alph2 = Alphabet::new(alph2).ok_or(CipherError::RepeatingAlphabet)?;
        if alph1.len() != alph2.len() {
            Err(CipherError::RepeatingAlphabet)
        } else {
            Ok(Self { alph1, alph2 })
        }
    }
}

impl Cipher for SubstitutionCipher {
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CipherError> {
        substitue(&self.alph1, &self.alph2, message)
    }

    fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CipherError> {
        substitue(&self.alph2, &self.alph1, cipher_text)
    }
}

#[cfg(test)]
mod substitution_cipher_test {
    use super::{Cipher, SubstitutionCipher};

    #[test]
    fn test_substitution_symmetric() {
        let alph1 = "ABCDEFG";
        let alph2 = "BCDEFGA";
        let cipher = SubstitutionCipher::new(alph1, alph2).unwrap();
        let message = "BECAGFFGFGAB";
        let cipher_text = cipher.encrypt(message.as_bytes()).unwrap();
        let restored_message = cipher.decrypt(&cipher_text).unwrap();
        assert_ne!(message.as_bytes(), cipher_text);
        assert_eq!(message.as_bytes(), restored_message);
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
    pub fn new(alph: impl AsRef<[u8]>, a: usize, b: usize) -> Result<Self, CipherError> {
        let alph = Alphabet::new(alph).ok_or(CipherError::RepeatingAlphabet)?;
        let m = alph.len();
        let inverse_a = absmod(
            modular_multiplicative_inverse(a as i64, m as i64).ok_or(CipherError::NotCoprime)?,
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
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CipherError> {
        message
            .as_ref()
            .iter()
            .copied()
            .map(|ch| match self.alph.get_index(&ch) {
                Some(x) => {
                    let y = (self.a * x + self.b) % self.alph.len();
                    Ok(self.alph.get_letter(&y).unwrap())
                }
                _ => Err(CipherError::UnknownCharacter(ch)),
            })
            .collect()
    }

    fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CipherError> {
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
                _ => Err(CipherError::UnknownCharacter(ch)),
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
        let cipher = AffineCipher::new(ALPH.as_bytes(), 376, 111).unwrap();
        let message = "Hello, world!";
        let cipher_text = cipher.encrypt(message.as_bytes()).unwrap();
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
    ) -> Result<Self, CipherError> {
        let alph = Alphabet::new(alph).ok_or(CipherError::RepeatingAlphabet)?;
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
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CipherError> {
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
                _ => Err(CipherError::UnknownCharacter(ch)),
            })
            .collect()
    }

    fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CipherError> {
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
                            .ok_or(CipherError::NotCoprime)?,
                        m as i64,
                    ) as usize;
                    let inverse_b = absmod(-(b as i64), m as i64) as usize;
                    let x = (inverse_a * (y + inverse_b)) % m;
                    Ok(self.alph.get_letter(&x).unwrap())
                }
                _ => Err(CipherError::UnknownCharacter(ch)),
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
        let cipher = AffineRecurrentCipher::new(ALPH.as_bytes(), 356, 357, 111, 112).unwrap();
        let msg = "Hello, world!";
        let cipher_text = cipher.encrypt(msg.as_bytes()).unwrap();
        let restored = cipher.decrypt(&cipher_text).unwrap();
        // println!("cipher_text: {:?}", String::from_utf8(cipher_text.clone()));
        // println!("restored: {:?}", String::from_utf8(restored.clone()));
        assert_eq!(msg.as_bytes(), restored);
    }
}
