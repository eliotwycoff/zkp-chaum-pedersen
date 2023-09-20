use crate::crypto::{ Challenge, Statement, Solution };
use error::SignerError;
use num_bigint::{ BigUint, RandBigInt };
use std::sync::Arc;

pub mod error;

pub struct Builder {
    generators: Option<(Arc<BigUint>, Arc<BigUint>)>,
    moduli: Option<(Arc<BigUint>, Arc<BigUint>)>,
    x: Option<Arc<BigUint>>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            generators: None,
            moduli: None,
            x: None,
        }
    }

    pub fn with_generators(mut self, alpha: u32, beta: u32) -> Result<Self, SignerError> {
        // TODO: Validate the generators.
        self.generators = Some((Arc::new(BigUint::from(alpha)), Arc::new(BigUint::from(beta))));

        Ok(self)
    }

    pub fn with_moduli(mut self, p: u32, q: u32) -> Result<Self, SignerError> {
        if self.generators.is_none() {
            return Err(SignerError::GeneratorsNotSet);
        }

        // TODO: Validate the moduli.
        self.moduli = Some((Arc::new(BigUint::from(p)), Arc::new(BigUint::from(q))));

        Ok(self)
    }

    pub fn with_secret(mut self, x: u32) -> Result<Self, SignerError> {
        if self.generators.is_none() {
            return Err(SignerError::GeneratorsNotSet);
        }

        if self.moduli.is_none() {
            return Err(SignerError::ModuliNotSet);
        }

        // TODO: Validate the secret.
        self.x = Some(Arc::new(BigUint::from(x)));

        Ok(self)
    }

    pub fn build(&self) -> Result<Signer, SignerError> {
        let (alpha, beta) = match &self.generators {
            Some((alpha, beta)) => (alpha.clone(), beta.clone()),
            None => {
                return Err(SignerError::GeneratorsNotSet);
            }
        };

        let (p, q) = match &self.moduli {
            Some((p, q)) => (p.clone(), q.clone()),
            None => {
                return Err(SignerError::ModuliNotSet);
            }
        };

        let x = match &self.x {
            Some(x) => x.clone(),
            None => Arc::new(rand::thread_rng().gen_biguint_below(&q)),
        };

        let k = Arc::new(rand::thread_rng().gen_biguint_below(&q));

        Ok(Signer {
            alpha,
            beta,
            p,
            q,
            x,
            k,
        })
    }
}

pub struct Signer {
    alpha: Arc<BigUint>,
    beta: Arc<BigUint>,
    p: Arc<BigUint>,
    q: Arc<BigUint>,
    x: Arc<BigUint>,
    k: Arc<BigUint>,
}

impl Signer {
    pub fn create_statement(&self) -> Statement {
        let y = (self.alpha.modpow(&self.x, &self.p), self.beta.modpow(&self.x, &self.p));
        let r = (self.alpha.modpow(&self.k, &self.p), self.beta.modpow(&self.k, &self.p));

        Statement {
            alpha: (*self.alpha).clone(),
            beta: (*self.beta).clone(),
            p: (*self.p).clone(),
            y,
            r,
        }
    }

    /// Finds a solution to the given challenge, i.e. solves for `s` where
    /// `s = k - (c * x) mod q`.
    pub fn solve_challenge(&self, c: Challenge) -> Solution {
        let cx = c * &*self.x;

        if *self.k >= cx {
            (&*self.k - cx).modpow(&BigUint::from(1u32), &self.q)
        } else {
            &*self.q - (cx - &*self.k).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    #[cfg(test)]
    pub fn override_k(&mut self, k: u32) {
        self.k = Arc::new(BigUint::from(k));
    }

    #[cfg(test)]
    pub fn q(&self) -> &BigUint {
        &*self.q
    }
}
