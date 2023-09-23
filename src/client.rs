use inquire::{
    max_length, min_length, validator::Validation, Password, PasswordDisplayMode, Select, Text,
};
use lib::{
    grpc::auth::{AuthClient, AuthRequest, CommitRequest, SessionId, SignUpRequest, Username},
    zkp::{
        signer::Signer, Group, MODP_0005_004_GROUP, MODP_1024_160_GROUP, MODP_2048_224_GROUP,
        MODP_2048_256_GROUP,
    },
};
use std::{collections::HashMap, str::FromStr};
use tonic::Request;
use uuid::Uuid;

mod config;

enum ClientState {
    Home,
    Register,
    Authenticate(Username),
    Authenticated(SessionId),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate the gRPC client.
    let address = format!("http://{}", config::SHARED.auth_server_address);
    let mut auth_client = AuthClient::connect(address).await?;

    // Initialize the client state.
    let mut usernames = HashMap::<Username, &'static Group>::new();
    let mut client_state = ClientState::Home;

    // Begin the client loop.
    'main: loop {
        match client_state {
            ClientState::Home => {
                // Define the home menu.
                let register = "Register new user";
                let authenticate = "Authenticate user";
                let exit = "Exit";

                // Get the user's menu selection.
                let options = if usernames.len() > 0 {
                    vec![register, authenticate, exit]
                } else {
                    vec![register, exit]
                };
                let selection = Select::new("What would you like to do?", options)
                    .with_page_size(3)
                    .prompt()?;

                if selection == register {
                    client_state = ClientState::Register;
                    continue 'main;
                } else if selection == authenticate {
                    // Select a user.
                    let username = Select::new(
                        "Please select a user to authenticate:",
                        usernames.keys().collect(),
                    )
                    .with_page_size(10)
                    .prompt()?;

                    client_state = ClientState::Authenticate(username.clone());
                    continue 'main;
                } else if selection == exit {
                    println!("Goodbye!");
                    break 'main;
                } else {
                    println!("Unknown selection. Returning home.");
                    continue 'main;
                }
            }
            ClientState::Register => {
                // Ask the user to choose which mod-p group they'd like to use.
                let groups = vec![
                    ("0005-Bit P, 004-Bit Q", &*MODP_0005_004_GROUP),
                    ("1024-Bit P, 160-Bit Q", &*MODP_1024_160_GROUP),
                    ("2048-Bit P, 224-Bit Q", &*MODP_2048_224_GROUP),
                    ("2048-Bit P, 256-Bit Q", &*MODP_2048_256_GROUP),
                ];

                let group_names: Vec<&str> = groups.iter().map(|g| g.0).collect();
                let group_name = Select::new("Select encryption group:", group_names)
                    .with_page_size(10)
                    .prompt()?;
                let group = groups
                    .iter()
                    .find(|t| t.0 == group_name)
                    .expect("Encryption group does not exist")
                    .1;

                // Ask the user to input a username, and make sure it's unique.
                let taken: Vec<Username> = usernames.keys().cloned().collect();
                let is_unique = move |input: &str| match taken.iter().find(|u| u.as_str() == input)
                {
                    Some(_) => Ok(Validation::Invalid("Username already taken".into())),
                    None => Ok(Validation::Valid),
                };

                let username = Text::new("Username:")
                    .with_validator(min_length!(1, "Minimum of 1 character"))
                    .with_validator(max_length!(24, "Maximum of 24 characters"))
                    .with_validator(is_unique)
                    .prompt()?;

                // Ask the user to input a password.
                let password = Password::new("Password:")
                    .with_display_toggle_enabled()
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .with_validator(min_length!(8, "Minimum 8 characters"))
                    .prompt()?;

                // Send the sign up request via the auth client.
                let signer = Signer::try_from(group)?;
                let secret = signer.create_secret_from_password(password);
                let signature = Some(signer.create_signature(&secret));

                match auth_client
                    .sign_up(Request::new(SignUpRequest {
                        username: username.clone(),
                        signature,
                    }))
                    .await
                {
                    Ok(_) => {
                        println!("Successfully registered {}", username);
                        usernames.insert(username, group);
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                    Err(status) => {
                        println!("Failed to register user: {}", status.message());
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                }
            }
            ClientState::Authenticate(username) => {
                // Get the cryptographic group.
                let group = match usernames.get(&username) {
                    Some(group) => *group,
                    None => {
                        println!("Group not found");
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                };

                // Send the commitment request via the auth client.
                let signer = Signer::try_from(group)?;
                let commitment = Some(signer.create_commitment());
                let response = match auth_client
                    .commit(Request::new(CommitRequest {
                        username: username.clone(),
                        commitment,
                    }))
                    .await
                {
                    Ok(response) => response.into_inner(),
                    Err(status) => {
                        println!("Failed to submit commitment: {}", status.message());
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                };
                let verifier_id = response.verifier_id;
                let challenge = match response.challenge {
                    Some(challenge) => challenge,
                    None => {
                        println!("Auth server failed to return a challenge");
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                };

                // Ask the user to input the password for this username.
                let password = Password::new(&format!("Enter password for {}:", username))
                    .with_display_toggle_enabled()
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .with_validator(min_length!(8, "Minimum 8 characters"))
                    .prompt()?;

                // Send the authentication request via the auth client.
                let secret = signer.create_secret_from_password(password);
                let solution = Some(signer.create_solution(&secret, challenge));
                let response = match auth_client
                    .authenticate(Request::new(AuthRequest {
                        verifier_id,
                        solution,
                    }))
                    .await
                {
                    Ok(response) => response.into_inner(),
                    Err(status) => {
                        println!("Failed to make auth request: {}", status.message());
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                };

                // Extract the session id from the response.
                let session_id = match Uuid::from_str(response.session_id.as_str()) {
                    Ok(session_id) => session_id,
                    Err(error) => {
                        println!("Failed to decode session id: {}", error);
                        client_state = ClientState::Home;
                        continue 'main;
                    }
                };

                println!("Welcome back, {}!", username);
                client_state = ClientState::Authenticated(session_id);
                continue 'main;
            }
            ClientState::Authenticated(session_id) => {
                // Define the authenticated home menu.
                let get_session_id = "Reveal session id";
                let get_price = "Get the price of Bitcoin";
                let log_out = "Log out";

                // Get the user's selection.
                let selection = Select::new(
                    "What would you like to do?",
                    vec![get_session_id, get_price, log_out],
                )
                .with_page_size(3)
                .prompt()?;

                if selection == get_session_id {
                    println!("Your session id is {}", session_id);
                    continue 'main;
                } else if selection == get_price {
                    // TODO: For fun, call out to an external API.
                    println!("Not implemented yet!");
                    continue 'main;
                } else if selection == log_out {
                    client_state = ClientState::Home;
                    continue 'main;
                } else {
                    println!("Unknown selection. Returning home.");
                    client_state = ClientState::Home;
                    continue 'main;
                }
            }
        }
    }

    Ok(())
}
