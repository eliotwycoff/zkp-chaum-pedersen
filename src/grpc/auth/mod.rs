use crate::zkp::verifier::Verifier;
pub use auth::{
    auth_client::AuthClient,
    auth_server::{Auth, AuthServer},
    AuthRequest, AuthResponse, Challenge, CommitRequest, CommitResponse, Commitment,
    GetGroupRequest, GetGroupResponse, GetPriceRequest, GetPriceResponse, Group, SignUpRequest,
    SignUpResponse, Signature, Solution,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use uuid::Uuid;

mod auth;

type Username = String;
type VerifierId = Uuid;

#[derive(Debug, Default)]
pub struct AuthService {
    group: Group,
    signatures: RwLock<HashMap<Username, Signature>>,
    verifiers: RwLock<HashMap<VerifierId, Verifier>>,
}

impl AuthService {
    pub fn new(group: Group) -> Self {
        Self {
            group,
            signatures: RwLock::new(HashMap::new()),
            verifiers: RwLock::new(HashMap::new()),
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn get_group(
        &self,
        _: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        Ok(Response::new(GetGroupResponse {
            group: self.group.into(),
        }))
    }

    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<SignUpResponse>, Status> {
        let request = request.into_inner();

        // Make sure a signature was actually passed.
        let signature = request
            .signature
            .ok_or_else(|| Status::invalid_argument("Signature required"))?;

        // TODO: Validate the username.

        // Make sure the username doesn't already exist.
        if self.signatures.read().get(&request.username).is_some() {
            return Err(Status::already_exists("Username already exists"));
        }

        // Safely store the (username, signature) pair (in memory, for demo purposes).
        self.signatures.write().insert(request.username, signature);

        Ok(Response::new(SignUpResponse {}))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let request = request.into_inner();

        // Make sure a commitment was actually passed.
        let commitment = request
            .commitment
            .ok_or_else(|| Status::invalid_argument("Commitment required"))?;

        // TODO: Validate the username.

        // Make sure the username exists, and get the signature.
        let signature = match self.signatures.read().get(&request.username) {
            Some(signature) => signature.clone(),
            None => return Err(Status::not_found("Username not found")),
        };

        // Create and safely store the verifier (in memory, for demo purposes).
        let verifier = Verifier::try_from((self.group, signature, commitment))?;
        let verifier_id = Uuid::new_v4();
        let verifier_id_string = verifier_id.to_string();
        let challenge = verifier.create_challenge();

        self.verifiers.write().insert(verifier_id, verifier);

        Ok(Response::new(CommitResponse {
            verifier_id: verifier_id_string,
            challenge: Some(challenge),
        }))
    }

    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        todo!()
    }

    async fn get_price(
        &self,
        request: Request<GetPriceRequest>,
    ) -> Result<Response<GetPriceResponse>, Status> {
        todo!()
    }
}
