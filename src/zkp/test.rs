use crate::{
    grpc::auth::Group,
    zkp::{signer::Signer, verifier::Verifier},
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn test_valid_solution_for_group(group: Group) -> TestResult<()> {
    // Set up the signer and get a commitment.
    let signer = Signer::try_from(group)?;
    let secret = signer.create_secret();
    let signature = signer.create_signature(&secret);
    let commitment = signer.create_commitment();

    // Set up the verifier and get a challenge.
    let verifier = Verifier::try_from((group, signature, commitment))?;
    let challenge = verifier.create_challenge();

    // Create a valid solution to the challenge.
    let solution = signer.create_solution(&secret, challenge);

    // Test to make sure that the solution passes.
    assert!(verifier.verify_solution(solution));

    Ok(())
}

fn test_invalid_solution_for_group(group: Group) -> TestResult<()> {
    // Set up the signer and get a commitment.
    let signer = Signer::try_from(group)?;
    let secret = signer.create_secret();
    let signature = signer.create_signature(&secret);
    let commitment = signer.create_commitment();

    // Set up the verifier and get a challenge.
    let verifier = Verifier::try_from((group, signature, commitment))?;
    let challenge = verifier.create_challenge();

    // Create an invalid solution to the challenge.
    let solution = signer.create_invalid_solution(&secret, challenge);

    assert!(!verifier.verify_solution(solution));

    Ok(())
}

#[test]
fn valid_4_bit_q_group_solution_passes() -> TestResult<()> {
    test_valid_solution_for_group(Group::ModP004BitQGroup)
}

#[test]
fn invalid_4_bit_q_group_solution_is_rejected() -> TestResult<()> {
    test_invalid_solution_for_group(Group::ModP004BitQGroup)
}

#[test]
fn valid_160_bit_q_group_solution_passes() -> TestResult<()> {
    test_valid_solution_for_group(Group::ModP160BitQGroup)
}

#[test]
fn invalid_160_bit_q_group_solution_is_rejected() -> TestResult<()> {
    test_invalid_solution_for_group(Group::ModP160BitQGroup)
}

#[test]
fn valid_224_bit_q_group_solution_passes() -> TestResult<()> {
    test_valid_solution_for_group(Group::ModP224BitQGroup)
}

#[test]
fn invalid_224_bit_q_group_solution_is_rejected() -> TestResult<()> {
    test_invalid_solution_for_group(Group::ModP224BitQGroup)
}

#[test]
fn valid_256_bit_q_group_solution_passes() -> TestResult<()> {
    test_valid_solution_for_group(Group::ModP256BitQGroup)
}

#[test]
fn invalid_256_bit_q_group_solution_is_rejected() -> TestResult<()> {
    test_invalid_solution_for_group(Group::ModP256BitQGroup)
}
