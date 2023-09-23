use crate::{
    grpc::auth::{Challenge, Commitment, Signature, Solution},
    zkp::{Error, Group},
};
use num_bigint::{BigUint, RandBigInt};

#[derive(Debug)]
pub struct Verifier {
    group: Group,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    c: BigUint,
}

impl Verifier {
    pub fn create_challenge(&self) -> Challenge {
        Challenge {
            c: self.c.to_bytes_be(),
        }
    }

    /// Verifies that the given solution satisifes the commitment, i.e.
    /// checks that `r1 = alpha^s * y1^c` and `r2 = beta^s * y2^c`.
    pub fn verify_solution(&self, solution: Solution) -> bool {
        let one = BigUint::from(1u32);
        let s = BigUint::from_bytes_be(&solution.s);

        let c1 = self.r1
            == (self.group.alpha.modpow(&s, &self.group.p)
                * self.y1.modpow(&self.c, &self.group.p))
            .modpow(&one, &self.group.p);

        let c2 = self.r2
            == (self.group.beta.modpow(&s, &self.group.p) * self.y2.modpow(&self.c, &self.group.p))
                .modpow(&one, &self.group.p);

        c1 && c2
    }
}

impl TryFrom<(Signature, Commitment)> for Verifier {
    type Error = Error;

    fn try_from((signature, commitment): (Signature, Commitment)) -> Result<Self, Self::Error> {
        let group = Group::from(&signature.group.ok_or_else(|| Error::GroupNotSpecified)?);

        let y1 = BigUint::from_bytes_be(&signature.y1);
        let y2 = BigUint::from_bytes_be(&signature.y2);
        let r1 = BigUint::from_bytes_be(&commitment.r1);
        let r2 = BigUint::from_bytes_be(&commitment.r2);
        let c = rand::thread_rng().gen_biguint_below(&group.q);

        Ok(Self {
            group,
            y1,
            y2,
            r1,
            r2,
            c,
        })
    }
}
