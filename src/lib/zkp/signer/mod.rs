use crate::{
    grpc::auth::{Challenge, Commitment, Signature, Solution},
    zkp::Group,
};
use num_bigint::{BigUint, RandBigInt};

pub struct Signer {
    group: &'static Group,
    k: BigUint,
}

impl Signer {
    pub fn create_random_secret(&self) -> BigUint {
        rand::thread_rng().gen_biguint_below(&self.group.q)
    }

    pub fn create_secret_from_password(&self, password: String) -> BigUint {
        // This should be salted before using in an actual production environment.
        BigUint::from_bytes_be(sha256::digest(password).as_bytes())
            .modpow(&BigUint::from(1u32), &self.group.q)
    }

    pub fn create_signature(&self, secret: &BigUint) -> Signature {
        Signature {
            group: Some(self.group.to_proto()),
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

impl From<&'static Group> for Signer {
    fn from(group: &'static Group) -> Self {
        let k = rand::thread_rng().gen_biguint_below(&group.q);

        Self { group, k }
    }
}
