fn main() {
    let cfg = privex_server::config::Config::from_env().expect("failed to load config from env");
    println!("VITE_KT_SIGNING_PUB={}", cfg.kt_signing_pub_hex());
    println!("VITE_TIME_SIGNING_PUB={}", cfg.time_signing_pub_hex());
}
