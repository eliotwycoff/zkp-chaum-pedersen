use num_bigint::BigUint;

pub mod signer;
pub mod verifier;

pub struct Statement {
    pub alpha: BigUint,
    pub beta: BigUint,
    pub p: BigUint,
    pub y: (BigUint, BigUint),
    pub r: (BigUint, BigUint),
}

pub type Challenge = BigUint;
pub type Solution = BigUint;

#[cfg(test)]
mod test;
