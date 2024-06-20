use std::collections::BTreeMap;
use std::convert::TryInto;
use std::iter::FromIterator;

use crate::constants::{D_DISPLAY_PLACES, TOTAL_TOKENS};
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod error_utils;
pub mod script_utils;
pub mod test_utils;
pub mod transaction_utils;

// ------- FUNCTIONS ------- //

/// Determines whether the passed value is within bounds of
/// available tokens in the supply.
///
/// TODO: Currently placeholder, needs to be filled in once requirements known
pub fn is_valid_amount(_value: &TokenAmount) -> bool {
    true
}

/// Formats an incoming value to be displayed
///
/// ### Arguments
///
/// * `value`   - Value to format for display
pub fn format_for_display(value: &u64) -> String {
    if value < &TOTAL_TOKENS {
        let value_f64 = *value as f64;
        return (value_f64 / D_DISPLAY_PLACES).to_string();
    }

    "Value out of bounds".to_string()
}

/// Create a single `BTreeMap<E, T>` struct from two `BTreeMap<E, T>` structs
/// , summing the values of `T` for each corresponding entry `E`
///
/// ### Arguments
///
/// * `m1` - First map
/// * `m2` - Second map
pub fn add_btreemap<E: Ord, T: Copy + std::ops::AddAssign>(
    m1: &mut BTreeMap<E, T>,
    m2: BTreeMap<E, T>,
) -> &BTreeMap<E, T> {
    m2.into_iter().for_each(|(key, value)| {
        m1.entry(key).and_modify(|e| *e += value).or_insert(value);
    });
    m1
}

trait ArrayFromIterator<E> : Sized {
    type Error;

    fn array_from_iter<I: IntoIterator<Item = E>>(iter: I) -> Result<Self, Self::Error>;
}

impl<T, const N: usize> ArrayFromIterator<T> for [T; N] {
    type Error = Vec<T>;

    fn array_from_iter<I: IntoIterator<Item=T>>(iter: I) -> Result<Self, Self::Error> {
        iter.into_iter().collect::<Vec<T>>().try_into()
    }
}

impl<T, E, const N: usize> ArrayFromIterator<Result<T, E>> for Result<[T; N], E> {
    type Error = Vec<T>;

    fn array_from_iter<I: IntoIterator<Item=Result<T, E>>>(iter: I) -> Result<Self, Self::Error> {
        match iter.into_iter().collect::<Result<Vec<T>, E>>() {
            Ok(vec) => vec.try_into().map(Ok),
            Err(err) => Ok(Err(err)),
        }
    }
}

pub trait IntoArray {
    type Item;

    /// Alternative to `Iterator.collect()` which allows collecting the values directly into
    /// an array.
    ///
    /// This is unfortunately required because there is no standard library implementation of
    /// FromIterator for arbitrary array types, so we need to add our own trait for it.
    fn into_array<T: ArrayFromIterator<Self::Item>>(self) -> Result<T, T::Error>;
}

impl<I: Iterator> IntoArray for I {
    type Item = I::Item;

    fn into_array<T: ArrayFromIterator<Self::Item>>(self) -> Result<T, T::Error> {
        T::array_from_iter(self)
    }
}
