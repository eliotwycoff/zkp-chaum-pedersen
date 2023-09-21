use crate::{
    crypto::{
        CryptoError, GroupParams, MOD_P_004_BIT_Q_GROUP, MOD_P_160_BIT_Q_GROUP,
        MOD_P_224_BIT_Q_GROUP, MOD_P_256_BIT_Q_GROUP,
    },
    grpc::auth::{Challenge, Commitment, Group, Signature, Solution},
};
use num_bigint::{BigUint, RandBigInt};

pub struct Verifier {
    group: &'static GroupParams,
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
    /// checks that `r0 = alpha^s * y1^c` and `r1 = beta^s * y1^c`.
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

impl TryFrom<(Group, Signature, Commitment)> for Verifier {
    type Error = CryptoError;

    fn try_from(
        (group, signature, commitment): (Group, Signature, Commitment),
    ) -> Result<Self, Self::Error> {
        let params = match group {
            Group::ModP004BitQGroup => &*MOD_P_004_BIT_Q_GROUP,
            Group::ModP160BitQGroup => &*MOD_P_160_BIT_Q_GROUP,
            Group::ModP224BitQGroup => &*MOD_P_224_BIT_Q_GROUP,
            Group::ModP256BitQGroup => &*MOD_P_256_BIT_Q_GROUP,
            Group::UnspecifiedGroup => return Err(CryptoError::GroupNotSpecified),
        };

        let y1 = BigUint::from_bytes_be(&signature.y1);
        let y2 = BigUint::from_bytes_be(&signature.y2);
        let r1 = BigUint::from_bytes_be(&commitment.r1);
        let r2 = BigUint::from_bytes_be(&commitment.r2);
        let c = rand::thread_rng().gen_biguint_below(&params.q);

        Ok(Self {
            group: params,
            y1,
            y2,
            r1,
            r2,
            c,
        })
    }
}
