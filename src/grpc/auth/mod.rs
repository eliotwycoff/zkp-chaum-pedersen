use crate::zkp::verifier::Verifier;
pub use auth::{
    auth_client::AuthClient,
    auth_server::{Auth, AuthServer},
    AuthRequest, AuthResponse, Challenge, CommitRequest, CommitResponse, Commitment,
    GetGroupRequest, GetGroupResponse, GetPriceRequest, GetPriceResponse, Group, SignUpRequest,
    SignUpResponse, Signature, Solution,
};
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

mod auth;

type Username = String;
type VerifierId = Uuid;
type SessionId = Uuid;

#[derive(Debug, Default)]
pub struct AuthService {
    group: Group,
    signatures: RwLock<HashMap<Username, Signature>>,
    verifiers: RwLock<HashMap<VerifierId, Verifier>>,
    sessions: RwLock<HashSet<SessionId>>,
}

impl AuthService {
    pub fn new(group: Group) -> Self {
        Self {
            group,
            signatures: RwLock::new(HashMap::new()),
            verifiers: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashSet::new()),
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn get_group(
        &self,
        _: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        // Return the group (encryption protocol) to the client.
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

        // Make sure the username exists, and get the signature.
        let signature = match self.signatures.read().get(&request.username) {
            Some(signature) => signature.clone(),
            None => return Err(Status::not_found("Username not found")),
        };

        // Create and the verifier from the signature and commitment.
        let verifier = Verifier::try_from((self.group, signature, commitment))?;

        // Create the authentication challenge for the client.
        let verifier_id = Uuid::new_v4();
        let verifier_id_string = verifier_id.to_string();
        let challenge = verifier.create_challenge();

        // Safely store the verifier (in memory, for demo purposes).
        self.verifiers.write().insert(verifier_id, verifier);

        // Return the verifier id and challenge to the client.
        Ok(Response::new(CommitResponse {
            verifier_id: verifier_id_string,
            challenge: Some(challenge),
        }))
    }

    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let request = request.into_inner();

        // Make sure that a solution was actually passed.
        let solution = request
            .solution
            .ok_or_else(|| Status::invalid_argument("Solution required"))?;

        // Get the verifier, if it exists.
        let verifier_id = Uuid::from_str(request.verifier_id.as_str())
            .map_err(|_| Status::invalid_argument("Invalid verifier_id"))?;
        let verifier = self
            .verifiers
            .write()
            .remove(&verifier_id)
            .ok_or_else(|| Status::not_found("Verifier not found"))?;

        if verifier.verify_solution(solution) {
            // Create and safely store a session_id (in memory, for demo purposes);
            let session_id = Uuid::new_v4();
            let session_id_string = session_id.to_string();

            self.sessions.write().insert(session_id);

            // Return the session id to the client.
            Ok(Response::new(AuthResponse {
                session_id: session_id_string,
            }))
        } else {
            Err(Status::unauthenticated("Authentication failed"))
        }
    }

    async fn get_price(
        &self,
        request: Request<GetPriceRequest>,
    ) -> Result<Response<GetPriceResponse>, Status> {
        let request = request.into_inner();

        // Reject invalid session ids.
        let session_id = Uuid::from_str(request.session_id.as_str())
            .map_err(|_| Status::invalid_argument("Invalid session_id"))?;

        if self.sessions.read().get(&session_id).is_none() {
            return Err(Status::unauthenticated("Not authenticated"));
        }

        // TODO: For fun, fetch a live crypto price... or something like that.

        Ok(Response::new(GetPriceResponse {
            symbol: request.symbol,
            price: String::from("27538.23"),
        }))
    }
}
