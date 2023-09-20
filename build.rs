fn main() {
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .build_server(true)
        .build_client(true)
        .out_dir("src/grpc/auth/")
        .compile(&["proto/auth.proto"], &["proto/"])
        .expect("Failed to build auth protobufs");

    println!("cargo:rerun-if-changed=proto/auth.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
