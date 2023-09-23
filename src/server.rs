use lib::grpc::auth::{AuthServer, AuthService};

mod config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = config::SHARED
        .auth_server_address
        .parse::<std::net::SocketAddr>()?;

    println!("Starting the authentication server at {}", address);

    // Start the gRPC authentication server.
    tonic::transport::Server::builder()
        .add_service(AuthServer::new(AuthService::new()))
        .serve(address)
        .await?;

    Ok(())
}
