use tonic::{transport::Server, Code, Request, Response, Status};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("I am the server!");

    Ok(())
}
