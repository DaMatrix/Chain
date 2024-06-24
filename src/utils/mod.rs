use std::collections::BTreeMap;
use std::convert::TryInto;

use crate::constants::{D_DISPLAY_PLACES, TOTAL_TOKENS};
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod script_utils;
pub mod serialize_utils;
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

/// Allows pattern matching a slice with a constant length array.
///
/// ### Arguments
///
/// * `slice` - the slice to match
pub fn array_match_slice<T, const N: usize>(slice: &[T]) -> Option<&[T; N]> {
    slice.try_into().ok()
}

/// Allows pattern matching a slice with a constant length array.
///
/// ### Arguments
///
/// * `slice` - the slice to match
pub fn array_match_slice_copy<T: Copy, const N: usize>(slice: &[T]) -> Option<[T; N]> {
    slice.try_into().ok()
}

/// A trait which indicates that it is possible to acquire a "placeholder" value
/// of a type, which can be used for test purposes.
pub trait Placeholder : Sized {
    /// Gets a dummy value of this type which can be used for test purposes.
    fn placeholder() -> Self {
        Self::placeholder_indexed(0)
    }

    /// Gets a dummy valid of this type which can be used for test purposes.
    ///
    /// This allows acquiring multiple distinct placeholder values which are still consistent
    /// between runs.
    ///
    /// ### Arguments
    ///
    /// * `index`  - the index of the dummy value to obtain
    fn placeholder_indexed(index: u64) -> Self;
}

/// A trait which indicates that a type can be represented by an ordinal number.
pub trait ToOrdinal {
    /// Gets the ordinal number from a value.
    fn to_ordinal(&self) -> u32;
}

/// A trait which indicates that a type can be instantiated from an ordinal number.
pub trait FromOrdinal : Sized {
    /// A slice containing every valid ordinal number.
    const ALL_ORDINALS : &'static [u32];

    /// Gets the value corresponding to the given ordinal number.
    ///
    /// ### Arguments
    ///
    /// * `ordinal` - The ordinal number
    fn from_ordinal(ordinal: u32) -> Result<Self, u32>;
}

/// A trait which indicates that a type can be represented by a string name.
pub trait ToName {
    /// Gets a value's string name.
    fn to_name(&self) -> &'static str;
}

/// A trait which indicates that a type can be instantiated from a string name.
pub trait FromName : Sized {
    /// A slice containing every valid name.
    const ALL_NAMES : &'static [&'static str];

    /// Gets the value corresponding to the given name.
    ///
    /// ### Arguments
    ///
    /// * `name` - The name
    fn from_name(name: &str) -> Result<Self, &str>;
}

pub trait ArrayFromIterator<E> : Sized {
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
