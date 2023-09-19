use crate::crypto::{ signer::Signer, verifier::Verifier };
use num_bigint::BigUint;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn can_solve_and_verify_simple_example() -> TestResult<()> {
    let signer = Signer::from(
        BigUint::from(4u32), // alpha
        BigUint::from(9u32), // beta
        BigUint::from(23u32), // p
        BigUint::from(11u32), // q
        BigUint::from(6u32), // x
        BigUint::from(7u32) // k
    );

    let mut verifier = Verifier::from(signer.create_statement());

    verifier.set_c(BigUint::from(4u32));

    let solution = signer.solve_challenge(verifier.create_challenge());

    assert!(verifier.verify_solution(solution));

    Ok(())
}
