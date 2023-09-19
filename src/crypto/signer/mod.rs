use crate::crypto::{ Challenge, Statement, Solution };
use num_bigint::BigUint;

pub struct Signer {
    alpha: BigUint,
    beta: BigUint,
    p: BigUint,
    q: BigUint,
    x: BigUint,
    k: BigUint,
}

impl Signer {
    pub fn create_statement(&self) -> Statement {
        let y = (self.alpha.modpow(&self.x, &self.p), self.beta.modpow(&self.x, &self.p));
        let r = (self.alpha.modpow(&self.k, &self.p), self.beta.modpow(&self.k, &self.p));

        Statement {
            alpha: self.alpha.clone(),
            beta: self.beta.clone(),
            p: self.p.clone(),
            y,
            r,
        }
    }

    /// Finds a solution to the given challenge, i.e. solves for `s` where
    /// `s = k - (c * x) mod q`.
    pub fn solve_challenge(&self, c: Challenge) -> Solution {
        let cx = c * &self.x;

        if self.k >= cx {
            (&self.k - cx).modpow(&BigUint::from(1u32), &self.q)
        } else {
            &self.q - (cx - &self.k).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    #[cfg(test)]
    pub fn from(
        alpha: BigUint,
        beta: BigUint,
        p: BigUint,
        q: BigUint,
        x: BigUint,
        k: BigUint
    ) -> Self {
        Self {
            alpha,
            beta,
            p,
            q,
            x,
            k,
        }
    }
}
