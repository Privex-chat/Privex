// Privex server entrypoint. All logic lives in the library (src/lib.rs).
// Logging law: never log account identifiers, network addresses, request bodies,
// tokens, or key material - only static startup/shutdown lifecycle events.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    privex_server::run().await
}
