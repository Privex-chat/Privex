// Generate a fresh OPAQUE ServerSetup and print as base64.
// Run: cargo run --bin gen_opaque_setup
// Paste the output into OPAQUE_SERVER_SETUP in .env

fn main() {
    let setup = privex_server::crypto::opaque::new_setup();
    use base64::Engine as _;
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(&setup)
    );
}
