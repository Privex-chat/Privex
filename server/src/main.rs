// Privex server entrypoint. All logic lives in the library (src/lib.rs).
// Logging law: never log account identifiers, network addresses, request bodies,
// tokens, or key material - only static startup/shutdown lifecycle events.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    // `privex-server migrate` applies migrations and exits - the entrypoint for
    // the pre-deploy K8s Job (PVX-05), so serving pods never migrate on boot.
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        return privex_server::run_migrations_cli().await;
    }
    privex_server::run().await
}
