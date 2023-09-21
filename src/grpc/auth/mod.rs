use crate::zkp::verifier::Verifier;
pub use auth::{
    auth_client::AuthClient,
    auth_server::{Auth, AuthServer},
    AuthRequest, AuthResponse, Challenge, CommitRequest, CommitResponse, Commitment,
    GetGroupRequest, GetGroupResponse, Group, SignUpRequest, SignUpResponse, Signature, Solution,
};
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use uuid::Uuid;

mod auth;

type Username = String;
type VerifierId = Uuid;

#[derive(Debug, Default)]
pub struct AuthService {
    group: Group,
    signatures: HashMap<Username, Signature>,
    verifiers: HashMap<VerifierId, Verifier>,
}

impl AuthService {
    pub fn new(group: Group) -> Self {
        Self {
            group,
            signatures: HashMap::new(),
            verifiers: HashMap::new(),
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn get_group(
        &self,
        request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        todo!()
    }

    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<SignUpResponse>, Status> {
        todo!()
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        todo!()
    }

    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        todo!()
    }
}
