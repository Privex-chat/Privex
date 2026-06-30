// PoW solve bench (cargo bench). Solves difficulty=22 ten times and reports the
// average. Fails (regression) if the average exceeds 1000ms. harness = false.

use std::time::Instant;

use privex_crypto_wasm::{pow_solve_native, pow_verify};

fn main() {
    let difficulty = 22u32;
    let runs = 10u128;
    let mut total_ms = 0u128;

    for i in 0..runs {
        let mut challenge = b"privex-pow-bench-".to_vec();
        challenge.push(i as u8); // distinct challenge per run

        let start = Instant::now();
        let (nonce, _hash) = pow_solve_native(&challenge, difficulty);
        total_ms += start.elapsed().as_millis();

        assert!(pow_verify(&challenge, nonce, difficulty), "solution must verify");
    }

    let avg = total_ms / runs;
    println!("pow_solve difficulty={difficulty} avg: {avg} ms over {runs} runs");
    assert!(avg < 1000, "PoW solve regression: avg {avg}ms exceeds 1000ms");
}
