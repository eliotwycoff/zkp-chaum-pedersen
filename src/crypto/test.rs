use crate::crypto::{ signer::{ Builder, Signer }, verifier::Verifier };
use num_bigint::BigUint;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn test_setup_with_simple_signer(k: Option<u32>) -> TestResult<Signer> {
    let mut signer = Builder::new()
        .with_generators(4u32, 9u32)?
        .with_moduli(23u32, 11u32)?
        .with_secret(6u32)?
        .build()?;

    if let Some(k) = k {
        signer.override_k(k);
    }

    Ok(signer)
}

#[test]
fn can_build_signer_with_simple_values_and_fixed_k() -> TestResult<()> {
    let _ = test_setup_with_simple_signer(Some(7u32))?;

    Ok(())
}

#[test]
fn verifier_with_fixed_c_can_verify_solution_from_simple_signer_with_fixed_k() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(Some(7u32))?;
    let mut verifier = Verifier::from(signer.create_statement());

    verifier.override_c(4u32);

    let solution = signer.solve_challenge(verifier.create_challenge());

    assert!(verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn verifier_with_fixed_c_rejects_invalid_solution_from_simple_signer_with_fixed_k() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(Some(7u32))?;
    let mut verifier = Verifier::from(signer.create_statement());

    verifier.override_c(4u32);

    let solution = BigUint::from(2u32); // an invalid solution to the simple example

    assert!(!verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn can_build_signer_with_simple_values() -> TestResult<()> {
    let _ = test_setup_with_simple_signer(None)?;

    Ok(())
}

#[test]
fn verifier_with_fixed_c_can_verify_solution_from_simple_signer() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(None)?;
    let mut verifier = Verifier::from(signer.create_statement());

    verifier.override_c(4u32);

    let solution = signer.solve_challenge(verifier.create_challenge());

    assert!(verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn verifier_with_fixed_c_rejects_invalid_solution_from_simple_signer() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(None)?;
    let mut verifier = Verifier::from(signer.create_statement());

    verifier.override_c(4u32);

    let offset = BigUint::from(1u32);
    let solution = (signer.solve_challenge(verifier.create_challenge()) + offset).modpow(
        &BigUint::from(1u32),
        signer.q()
    );

    assert!(!verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn verifier_can_verify_solution_from_simple_signer() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(None)?;
    let verifier = Verifier::from(signer.create_statement());
    let solution = signer.solve_challenge(verifier.create_challenge());

    assert!(verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn verifier_rejects_invalid_solution_from_simple_signer() -> TestResult<()> {
    let signer = test_setup_with_simple_signer(None)?;
    let verifier = Verifier::from(signer.create_statement());
    let offset = BigUint::from(1u32);
    let solution = (signer.solve_challenge(verifier.create_challenge()) + offset).modpow(
        &BigUint::from(1u32),
        signer.q()
    );

    assert!(!verifier.verify_solution(solution));

    Ok(())
}
