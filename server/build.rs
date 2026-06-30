// Generate Rust types from the shared Protobuf schemas (prost). Output lands in
// OUT_DIR as `privex.rs` (package name), included by src/main.rs.
// Requires `protoc` on PATH.

fn main() {
    let proto_dir = "../packages/protocol/proto";
    let files = [
        "envelope.proto",
        "keys.proto",
        "calls.proto",
        "groups.proto",
        "recovery.proto",
        "messages.proto",
        "wire.proto",
    ];
    let paths: Vec<String> = files.iter().map(|f| format!("{proto_dir}/{f}")).collect();
    for p in &paths {
        println!("cargo:rerun-if-changed={p}");
    }
    prost_build::compile_protos(&paths, &[proto_dir]).expect("prost: failed to compile protos");
}
