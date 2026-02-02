extern crate alloc;

use crate::DecodeError;

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

/// Calculates number of padding bits when writing bits to an octet buffer
pub(crate) fn bitstring_padding_bits(len: usize) -> usize {
    let extra_bits = len % 8;

    // 0 extra bits mean no padding needed
    if extra_bits > 0 {
        8 - extra_bits
    } else {
        0
    }
}

/// Calculates required number octets for a certain bit vector length
pub(crate) fn bitstring_buffer_size(len: usize) -> usize {
    num::Integer::div_ceil(&len, &8usize)
}
