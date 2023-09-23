# Authentication Via Zero-Knowledge Proofs
This project is a **work-in-progress** demo of how authentication can be performed using a custom implementation of the Chaum-Pedersen Zero-Knowledge Proof protocol. Credit for the idea is due to Guido Giuntoli and his Udemy course on [ZKPs in Rust](https://www.udemy.com/course/zero-knowledge-proofs-in-rust/). 

The project contains code for an authentication server that accepts incoming authentication requests over gRPC. Users running a client can sign up and authenticate via a CLI. Because a Zero-Knowledge Proof is used to perform authentication, neither the user password nor its hash are sent over the wire. Once authenticated, the user is given access to protected routes on the server.

## Getting Started

Clone the repo.

```bash
git clone git@github.com:eliotwycoff/zkp-chaum-pedersen.git
```

Then, `cd` into the project directory.

```bash
cd zkp-chaum-pedersen
```

Run the authentication server.

```bash
cargo run --bin server
```

Then, in a separate terminal, run the client.

```bash
cargo run --bin client
```

Now that the client is running, the terminal will allow you to register a new user. This involves choosing an encryption group, a username and a password. 

Once you're done registering the user, the terminal will give you the option to try authenticating that user with the server. This involves inputting the user's password (if you remember it), which is used to generate the secret used in the Chaum-Pederson protocol. 

Generally speaking, authentication will fail if you enter the wrong password. But if you're using the weakest (5-bit) encryption group, the password space is so small that you'll be able to log in using a random password in about 1 in every 10 tries.

Because authentication is performed via ZKP, neither your password nor its hash are transmitted over the wire.

## Run Tests

```bash
cargo test
```