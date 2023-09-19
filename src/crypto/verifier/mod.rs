use crate::crypto::{ Challenge, Statement, Solution };
use num_bigint::BigUint;

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
        Self {
            alpha: statement.alpha,
            beta: statement.beta,
            p: statement.p,
            y: statement.y,
            r: statement.r,
            c: BigUint::from(1u32), // TODO: Generate this randomly
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

        let c1 =
            self.r.0 ==
            (self.alpha.modpow(&s, &self.p) * self.y.0.modpow(&self.c, &self.p)).modpow(
                &one,
                &self.p
            );

        let c2 =
            self.r.1 ==
            (self.beta.modpow(&s, &self.p) * self.y.1.modpow(&self.c, &self.p)).modpow(
                &one,
                &self.p
            );

        c1 && c2
    }

    #[cfg(test)]
    pub fn set_c(&mut self, c: BigUint) {
        self.c = c;
    }
}
