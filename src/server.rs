use lib::grpc::auth::{AuthServer, AuthService, Group};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ask the user to choose which mod-p group they'd like to use.
    let groups = vec![
        ("004-Bit Encryption", Group::ModP004BitQGroup),
        ("160-Bit Encryption", Group::ModP160BitQGroup),
        ("224-Bit Encryption", Group::ModP224BitQGroup),
        ("256-Bit Encryption", Group::ModP256BitQGroup),
    ];

    let group_names: Vec<&str> = groups.iter().map(|g| g.0).collect();
    let group_name = inquire::Select::new("Select encryption group:", group_names)
        .with_page_size(10)
        .prompt()?;
    let group = groups
        .iter()
        .find(|t| t.0 == group_name)
        .expect("Encryption group does not exist")
        .1;

    let address = "[::1]:50055".parse::<std::net::SocketAddr>()?;

    println!("Starting the authentication server at {}", address);

    // Start the gRPC authentication server.
    tonic::transport::Server::builder()
        .add_service(AuthServer::new(AuthService::new(group)))
        .serve(address)
        .await?;

    Ok(())
}
