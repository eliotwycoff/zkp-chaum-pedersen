use crate::crypto::{Challenge, Solution, Statement};
use num_bigint::{BigUint, RandBigInt};

pub struct Verifier {
    alpha: BigUint,
    beta: BigUint,
    p: BigUint,
    y: (BigUint, BigUint),
    r: (BigUint, BigUint),
    c: BigUint,
}

impl From<Statement> for Verifier {
    fn from(statement: Statement) -> Self {
        let c = rand::thread_rng().gen_biguint_below(&statement.group.p);

        Self {
            alpha: statement.group.alpha,
            beta: statement.group.beta,
            p: statement.group.p,
            y: statement.y,
            r: statement.r,
            c,
        }
    }
}

impl Verifier {
    pub fn create_challenge(&self) -> Challenge {
        self.c.clone()
    }

    /// Verifies that the given solution satisifes the problem statement, i.e. checks that
    /// `r0 = alpha^s * y1^c` and `r1 = beta^s * y1^c`.
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
