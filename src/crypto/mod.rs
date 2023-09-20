use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt};
use std::sync::Arc;

pub mod signer;
pub mod verifier;

lazy_static! {
    static ref MOD_P_2048_BIT_GROUP: Arc<Group> = {
        let p_str = r#"
            87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2
            5D2CEED4 435E3B00 E00DF8F1 D61957D4 FAF7DF45 61B2AA30
            16C3D911 34096FAA 3BF4296D 830E9A7C 209E0C64 97517ABD
            5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B
            6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C
            4FDB70C5 81B23F76 B63ACAE1 CAA6B790 2D525267 35488A0E
            F13C6D9A 51BFA4AB 3AD83477 96524D8E F6A167B5 A41825D9
            67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026
            C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3
            75F26375 D7014103 A4B54330 C198AF12 6116D227 6E11715F
            693877FA D7EF09CA DB094AE9 1E1A1597
        "#;

        let p_bytes = hex::decode(
            p_str
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .expect("Failed to decode 2048-bit-group p");

        let p = BigUint::from_bytes_be(&p_bytes);

        let q_str = r#"
            8CF83642 A709A097 B4479976 40129DA2 99B1A47D 1EB3750B
            A308B0FE 64F5FBD3
        "#;

        let q_bytes = hex::decode(
            q_str
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .expect("Failed to decode 2048-bit-group q");

        let q = BigUint::from_bytes_be(&q_bytes);

        let alpha_str = r#"
            3FB32C9B 73134D0B 2E775066 60EDBD48 4CA7B18F 21EF2054
            07F4793A 1A0BA125 10DBC150 77BE463F FF4FED4A AC0BB555
            BE3A6C1B 0C6B47B1 BC3773BF 7E8C6F62 901228F8 C28CBB18
            A55AE313 41000A65 0196F931 C77A57F2 DDF463E5 E9EC144B
            777DE62A AAB8A862 8AC376D2 82D6ED38 64E67982 428EBC83
            1D14348F 6F2F9193 B5045AF2 767164E1 DFC967C1 FB3F2E55
            A4BD1BFF E83B9C80 D052B985 D182EA0A DB2A3B73 13D3FE14
            C8484B1E 052588B9 B7D2BBD2 DF016199 ECD06E15 57CD0915
            B3353BBB 64E0EC37 7FD02837 0DF92B52 C7891428 CDC67EB6
            184B523D 1DB246C3 2F630784 90F00EF8 D647D148 D4795451
            5E2327CF EF98C582 664B4C0F 6CC41659
        "#;

        let alpha_bytes = hex::decode(
            alpha_str
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .expect("Failed to decode 2048-bit-group alpha");

        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let beta = alpha.modpow(&rand::thread_rng().gen_biguint_below(&q), &p);

        Arc::new(Group { p, q, alpha, beta })
    };
}

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct Group {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

pub struct Commitment {
    pub group: Group,
    pub y: (BigUint, BigUint),
    pub r: (BigUint, BigUint),
}

pub type Challenge = BigUint;
pub type Solution = BigUint;
