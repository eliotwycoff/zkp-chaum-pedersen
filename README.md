# Authentication Via Zero-Knowledge Proofs
This project is a **work-in-progress** demo of how authentication can be performed using a custom implementation of the Chaum-Pedersen Zero-Knowledge Proof protocol. 

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

Finally, in a separate terminal, run the client.

```bash
cargo run --bin client
```

...to be continued.

## Run Tests

```bash
cargo test
```

## Credits

Credit for the idea is due to Guido Giuntoli and his Udemy course on [ZKPs in Rust](https://www.udemy.com/course/zero-knowledge-proofs-in-rust/). 