extern crate alloc;

use bitvec::prelude::*;
use nom_bitvec::BSlice;

use crate::DecodeError;

pub(crate) fn write_into_vec_left_padded(
    bits: BSlice<'_, u8, Msb0>,
    vec: &mut alloc::vec::Vec<u8>,
) {
    let missing_bits = 8 - bits.len() % 8;
    if missing_bits == 8 {
        for slice in bits.chunks(8) {
            vec.push(slice.load_be());
        }
    } else {
        let mut padding = bitvec![u8, bitvec::prelude::Msb0; 0; missing_bits];
        padding.append(&mut bits.to_bitvec());
        for s in padding.chunks(8) {
            vec.push(s.load_be());
        }
    }
}

pub(crate) fn cast_nom_err<I, O>(error: nom::Err<DecodeError<I>>) -> nom::Err<DecodeError<O>>
where
    DecodeError<I>: Into<DecodeError<O>>,
{
    match error {
        nom::Err::Incomplete(i) => nom::Err::Incomplete(i),
        nom::Err::Error(e) => nom::Err::Error(e.into()),
        nom::Err::Failure(e) => nom::Err::Failure(e.into()),
    }
}
