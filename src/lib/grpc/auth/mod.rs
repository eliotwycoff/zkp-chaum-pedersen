use crate::zkp::verifier::Verifier;
pub use auth::{
    auth_client::AuthClient,
    auth_server::{Auth, AuthServer},
    AuthRequest, AuthResponse, Challenge, CommitRequest, CommitResponse, Commitment,
    GetPriceRequest, GetPriceResponse, ProtoGroup, SignUpRequest, SignUpResponse, Signature,
    Solution,
};
use num_bigint::BigUint;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, instrument, Span};
use uuid::Uuid;

mod auth;

pub type Username = String;
pub type SessionId = Uuid;
type VerifierId = Uuid;

#[derive(Debug, Default)]
pub struct AuthService {
    signatures: RwLock<HashMap<Username, Signature>>,
    verifiers: RwLock<HashMap<VerifierId, Verifier>>,
    sessions: RwLock<HashSet<SessionId>>,
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            signatures: RwLock::new(HashMap::new()),
            verifiers: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashSet::new()),
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    #[instrument(
        skip(self, request),
        fields(
            request_id = %Uuid::new_v4(),
            username = %request.get_ref().username,
            signature,
            group,
        )
    )]
    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<SignUpResponse>, Status> {
        let span = Span::current();
        let request = request.into_inner();

        // Make sure a signature was actually passed.
        let signature = request.signature.ok_or_else(|| {
            info!("Signature required");
            Status::invalid_argument("Signature required")
        })?;

        // Record y1 and y2 to the current tracing span.
        span.record("signature", signature.tracing_string().as_str());

        // Make sure that a group was passed with the signature.
        let group = match &signature.group {
            Some(group) => group,
            None => {
                info!("Group required");
                return Err(Status::invalid_argument("Group required"));
            }
        };

        // Record p, q, alpha and beta to the current tracing span.
        span.record("group", group.tracing_string().as_str());

        // Make sure the username doesn't already exist.
        if self.signatures.read().get(&request.username).is_some() {
            info!("Username already exists");
            return Err(Status::already_exists("Username already exists"));
        }

        // Safely store the (username, signature) pair (in memory, for demo purposes).
        self.signatures.write().insert(request.username, signature);
        debug!("Username and signature saved to memory");

        Ok(Response::new(SignUpResponse {}))
    }

    #[instrument(
        skip(self, request),
        fields(
            request_id = %Uuid::new_v4(),
            username = %request.get_ref().username,
            commitment,
        )
    )]
    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let span = Span::current();
        let request = request.into_inner();

        // Make sure a commitment was actually passed.
        let commitment = request
            .commitment
            .ok_or_else(|| Status::invalid_argument("Commitment required"))?;

        // Record r1 and r2 to the current tracing span.
        span.record("commitment", commitment.tracing_string().as_str());

        // Make sure the username exists, and get the signature.
        let signature = match self.signatures.read().get(&request.username) {
            Some(signature) => signature.clone(),
            None => {
                info!("Username not found");
                return Err(Status::not_found("Username not found"));
            }
        };

        // Create the verifier from the signature and commitment.
        let verifier = match Verifier::try_from((signature, commitment)) {
            Ok(verifier) => verifier,
            Err(error) => {
                error!("Failed to create verifier => {}", error);
                return Err(Status::internal("An internal error occurred"));
            }
        };

        // Create the authentication challenge for the client.
        let verifier_id = Uuid::new_v4();
        let verifier_id_string = verifier_id.to_string();
        let challenge = verifier.create_challenge();

        // Safely store the verifier (in memory, for demo purposes).
        self.verifiers.write().insert(verifier_id, verifier);
        debug!("Verifier saved in memory");

        // Return the verifier id and challenge to the client.
        Ok(Response::new(CommitResponse {
            verifier_id: verifier_id_string,
            challenge: Some(challenge),
        }))
    }

    #[instrument(
        skip(self, request),
        fields(
            request_id = %Uuid::new_v4(),
            verifier_id = %request.get_ref().verifier_id,
            solution,
        )
    )]
    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let span = Span::current();
        let request = request.into_inner();

        // Make sure that a solution was actually passed.
        let solution = request
            .solution
            .ok_or_else(|| Status::invalid_argument("Solution required"))?;

        // TODO: Record s to the current tracing span.

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

impl Signature {
    pub fn tracing_string(&self) -> String {
        format!(
            "{{y1: {}, y2: {}}}",
            BigUint::from_bytes_be(self.y1.as_slice()),
            BigUint::from_bytes_be(self.y2.as_slice()),
        )
    }
}

impl ProtoGroup {
    pub fn tracing_string(&self) -> String {
        format!(
            "{{p: {}, q: {}, alpha: {}, beta: {}}}",
            BigUint::from_bytes_be(self.p.as_slice()),
            BigUint::from_bytes_be(self.q.as_slice()),
            BigUint::from_bytes_be(self.alpha.as_slice()),
            BigUint::from_bytes_be(self.beta.as_slice()),
        )
    }
}

impl Commitment {
    pub fn tracing_string(&self) -> String {
        format!(
            "{{r1: {}, r2: {}}}",
            BigUint::from_bytes_be(self.r1.as_slice()),
            BigUint::from_bytes_be(self.r2.as_slice()),
        )
    }
}
