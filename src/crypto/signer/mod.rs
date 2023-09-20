use crate::crypto::{Challenge, Group, Solution, Statement, MOD_P_2048_BIT_GROUP};
use error::SignerError;
use num_bigint::{BigUint, RandBigInt};
use std::sync::Arc;

pub mod error;

pub struct Builder {
    group: Option<Arc<Group>>,
    x: Option<Arc<BigUint>>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            group: None,
            x: None,
        }
    }

    pub fn with_group(
        mut self,
        p: u32,
        q: u32,
        alpha: u32,
        beta: u32,
    ) -> Result<Self, SignerError> {
        // TODO: Validate the group.

        let group = Arc::new(Group {
            p: BigUint::from(p),
            q: BigUint::from(q),
            alpha: BigUint::from(alpha),
            beta: BigUint::from(beta),
        });

        self.group = Some(group);

        Ok(self)
    }

    pub fn with_2048_bit_group(mut self) -> Self {
        self.group = Some(MOD_P_2048_BIT_GROUP.clone());

        self
    }

    pub fn with_secret(mut self, x: u32) -> Result<Self, SignerError> {
        if self.group.is_none() {
            return Err(SignerError::GroupNotSet);
        }

        // TODO: Validate the secret.
        self.x = Some(Arc::new(BigUint::from(x)));

        Ok(self)
    }

    pub fn with_random_secret(mut self) -> Result<Self, SignerError> {
        match &self.group {
            Some(group) => {
                self.x = Some(Arc::new(rand::thread_rng().gen_biguint_below(&group.q)));

                Ok(self)
            }
            None => Err(SignerError::GroupNotSet),
        }
    }

    pub fn build(&self) -> Result<Signer, SignerError> {
        let group = match &self.group {
            Some(group) => (*group).clone(),
            None => {
                return Err(SignerError::GroupNotSet);
            }
        };

        let x = match &self.x {
            Some(x) => x.clone(),
            None => Arc::new(rand::thread_rng().gen_biguint_below(&group.q)),
        };

        let k = Arc::new(rand::thread_rng().gen_biguint_below(&group.q));

        Ok(Signer { group, x, k })
    }
}

pub struct Signer {
    group: Arc<Group>,
    x: Arc<BigUint>,
    k: Arc<BigUint>,
}

impl Signer {
    pub fn create_statement(&self) -> Statement {
        let y = (
            self.alpha().modpow(&self.x, self.p()),
            self.beta().modpow(&self.x, self.p()),
        );
        let r = (
            self.alpha().modpow(&self.k, self.p()),
            self.beta().modpow(&self.k, self.p()),
        );

        Statement {
            group: (*self.group).clone(),
            y,
            r,
        }
    }

    /// Finds a solution to the given challenge, i.e. solves for `s` where
    /// `s = k - (c * x) mod q`.
    pub fn solve_challenge(&self, c: Challenge) -> Solution {
        let cx = c * &*self.x;

        if *self.k >= cx {
            (&*self.k - cx).modpow(&BigUint::from(1u32), self.q())
        } else {
            self.q() - (cx - &*self.k).modpow(&BigUint::from(1u32), self.q())
        }
    }

    pub fn p(&self) -> &BigUint {
        &self.group.p
    }

    pub fn q(&self) -> &BigUint {
        &self.group.q
    }

    pub fn alpha(&self) -> &BigUint {
        &self.group.alpha
    }

    pub fn beta(&self) -> &BigUint {
        &self.group.beta
    }

    #[cfg(test)]
    pub fn override_k(&mut self, k: u32) {
        self.k = Arc::new(BigUint::from(k));
    }
}
