// Aggregate, label-free metrics (PVX-04). The no-log rule forbids PER-REQUEST
// logs, not high-cardinality-free counters (the difficulty_manager already proves
// aggregate telemetry is acceptable). Everything here is a process-wide counter
// or a pool gauge - NO user_id / IP / target / path labels, ever. Scrape only on
// the internal network.
//
// ponytail: status-class counters + a duration sum (average latency), not a full
// bucketed histogram. Add buckets only if p99 tracking is actually needed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::extract::State;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub responses_2xx: AtomicU64,
    pub responses_3xx: AtomicU64,
    pub responses_4xx: AtomicU64,
    pub responses_5xx: AtomicU64,
    /// Sum of request handling time, nanoseconds. average = this / requests_total.
    pub request_nanos_total: AtomicU64,
    /// Background expiry-sweep failures (PVX-11) - invisible without this counter.
    pub cleanup_failures_total: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            responses_2xx: AtomicU64::new(0),
            responses_3xx: AtomicU64::new(0),
            responses_4xx: AtomicU64::new(0),
            responses_5xx: AtomicU64::new(0),
            request_nanos_total: AtomicU64::new(0),
            cleanup_failures_total: AtomicU64::new(0),
        }
    }

    fn record(&self, status: u16, elapsed_nanos: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.request_nanos_total
            .fetch_add(elapsed_nanos, Ordering::Relaxed);
        let bucket = match status {
            200..=299 => &self.responses_2xx,
            300..=399 => &self.responses_3xx,
            400..=499 => &self.responses_4xx,
            _ => &self.responses_5xx,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }
}

pub static METRICS: Metrics = Metrics::new();

/// Count a cleanup-task failure (called from the expiry sweep).
pub fn record_cleanup_failure() {
    METRICS
        .cleanup_failures_total
        .fetch_add(1, Ordering::Relaxed);
}

/// Tower middleware: time each request and bump the status-class counters. No
/// path/method/identity is recorded.
pub async fn track(req: axum::extract::Request, next: Next) -> Response {
    let start = Instant::now();
    let res = next.run(req).await;
    METRICS.record(res.status().as_u16(), start.elapsed().as_nanos() as u64);
    res
}

/// GET /metrics - Prometheus text format. Mount on the internal network only.
pub async fn metrics_handler(State(st): State<AppState>) -> Response {
    let m = &METRICS;
    let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let body = format!(
        concat!(
            "# HELP privex_requests_total Total HTTP requests handled.\n",
            "# TYPE privex_requests_total counter\n",
            "privex_requests_total {}\n",
            "# HELP privex_responses_total HTTP responses by status class.\n",
            "# TYPE privex_responses_total counter\n",
            "privex_responses_total{{class=\"2xx\"}} {}\n",
            "privex_responses_total{{class=\"3xx\"}} {}\n",
            "privex_responses_total{{class=\"4xx\"}} {}\n",
            "privex_responses_total{{class=\"5xx\"}} {}\n",
            "# HELP privex_request_duration_nanos_total Summed request handling time (ns).\n",
            "# TYPE privex_request_duration_nanos_total counter\n",
            "privex_request_duration_nanos_total {}\n",
            "# HELP privex_cleanup_failures_total Background expiry-sweep failures.\n",
            "# TYPE privex_cleanup_failures_total counter\n",
            "privex_cleanup_failures_total {}\n",
            "# HELP privex_db_pool_connections Current sqlx pool connections.\n",
            "# TYPE privex_db_pool_connections gauge\n",
            "privex_db_pool_connections {}\n",
            "# HELP privex_db_pool_idle Idle sqlx pool connections.\n",
            "# TYPE privex_db_pool_idle gauge\n",
            "privex_db_pool_idle {}\n",
        ),
        g(&m.requests_total),
        g(&m.responses_2xx),
        g(&m.responses_3xx),
        g(&m.responses_4xx),
        g(&m.responses_5xx),
        g(&m.request_nanos_total),
        g(&m.cleanup_failures_total),
        st.db.size(),
        st.db.num_idle(),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}
