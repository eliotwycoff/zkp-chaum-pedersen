use crate::{
    grpc::auth::{Challenge, Commitment, Group, Signature, Solution},
    zkp::{
        Error, GroupParams, MOD_P_004_BIT_Q_GROUP, MOD_P_160_BIT_Q_GROUP, MOD_P_224_BIT_Q_GROUP,
        MOD_P_256_BIT_Q_GROUP,
    },
};
use num_bigint::{BigUint, RandBigInt};

pub struct Signer {
    group: &'static GroupParams,
    k: BigUint,
}

impl Signer {
    pub fn create_secret(&self) -> BigUint {
        rand::thread_rng().gen_biguint_below(&self.group.q)
    }

    pub fn create_signature(&self, secret: &BigUint) -> Signature {
        Signature {
            y1: self.group.alpha.modpow(secret, &self.group.p).to_bytes_be(),
            y2: self.group.beta.modpow(secret, &self.group.p).to_bytes_be(),
        }
    }

    pub fn create_commitment(&self) -> Commitment {
        Commitment {
            r1: self
                .group
                .alpha
                .modpow(&self.k, &self.group.p)
                .to_bytes_be(),
            r2: self.group.beta.modpow(&self.k, &self.group.p).to_bytes_be(),
        }
    }

    /// Finds a solution to the given challenge, i.e. solves for `s` where
    /// `s = k - (c * x) mod q`.
    pub fn create_solution(&self, secret: &BigUint, challenge: Challenge) -> Solution {
        let cx = BigUint::from_bytes_be(&challenge.c) * secret;

        let s = if self.k >= cx {
            (&self.k - cx).modpow(&BigUint::from(1u32), &self.group.q)
        } else {
            &self.group.q - (cx - &self.k).modpow(&BigUint::from(1u32), &self.group.q)
        };

        Solution { s: s.to_bytes_be() }
    }

    #[cfg(test)]
    /// Create a provably invalid solution to the challenge (for testing purposes).
    pub fn create_invalid_solution(&self, secret: &BigUint, challenge: Challenge) -> Solution {
        let s_valid = BigUint::from_bytes_be(&self.create_solution(secret, challenge).s);
        let offset = BigUint::from(1u32);
        let s_invalid = (s_valid + offset).modpow(&BigUint::from(1u32), &self.group.q);

        Solution {
            s: s_invalid.to_bytes_be(),
        }
    }
}

impl TryFrom<Group> for Signer {
    type Error = Error;

    fn try_from(group: Group) -> Result<Self, Self::Error> {
        let params = match group {
            Group::ModP004BitQGroup => &*MOD_P_004_BIT_Q_GROUP,
            Group::ModP160BitQGroup => &*MOD_P_160_BIT_Q_GROUP,
            Group::ModP224BitQGroup => &*MOD_P_224_BIT_Q_GROUP,
            Group::ModP256BitQGroup => &*MOD_P_256_BIT_Q_GROUP,
            Group::UnspecifiedGroup => return Err(Error::GroupNotSpecified),
        };

        let k = rand::thread_rng().gen_biguint_below(&params.q);

        Ok(Self { group: params, k })
    }
}
