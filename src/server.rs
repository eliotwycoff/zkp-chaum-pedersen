use lib::grpc::auth::{AuthServer, AuthService};
use tracing::info;

mod config;
mod telemetry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    telemetry::init_tracing("zkp.auth.server");

    let address = config::SHARED
        .auth_server_address
        .parse::<std::net::SocketAddr>()?;

    info!("Starting the ZKP auth server at {}", address);

    // Start the gRPC authentication server.
    tonic::transport::Server::builder()
        .add_service(AuthServer::new(AuthService::new()))
        .serve(address)
        .await?;

    Ok(())
}
