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

The terminal will prompt you to select an encryption group. After selecting one, the server will start.

Finally, in a separate terminal, run the client.

```bash
cargo run --bin client
```

...to be continued.

## Run Tests

```bash
cargo test
```