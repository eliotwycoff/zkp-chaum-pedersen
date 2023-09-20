use crate::crypto::{Challenge, Commitment, Solution};
use num_bigint::{BigUint, RandBigInt};

pub struct Verifier {
    alpha: BigUint,
    beta: BigUint,
    p: BigUint,
    y: (BigUint, BigUint),
    r: (BigUint, BigUint),
    c: BigUint,
}

impl From<Commitment> for Verifier {
    fn from(commitment: Commitment) -> Self {
        let c = rand::thread_rng().gen_biguint_below(&commitment.group.p);

        Self {
            alpha: commitment.group.alpha,
            beta: commitment.group.beta,
            p: commitment.group.p,
            y: commitment.y,
            r: commitment.r,
            c,
        }
    }
}

impl Verifier {
    pub fn create_challenge(&self) -> Challenge {
        self.c.clone()
    }

    /// Verifies that the given solution satisifes the commitment, i.e.
    /// checks that `r0 = alpha^s * y1^c` and `r1 = beta^s * y1^c`.
    pub fn verify_solution(&self, s: Solution) -> bool {
        let one = BigUint::from(1u32);

        let c1 = self.r.0
            == (self.alpha.modpow(&s, &self.p) * self.y.0.modpow(&self.c, &self.p))
                .modpow(&one, &self.p);

        let c2 = self.r.1
            == (self.beta.modpow(&s, &self.p) * self.y.1.modpow(&self.c, &self.p))
                .modpow(&one, &self.p);

        c1 && c2
    }

    #[cfg(test)]
    pub fn override_c(&mut self, c: u32) {
        self.c = BigUint::from(c);
    }
}
