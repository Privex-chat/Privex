use std::time::Duration;

use deadpool_redis::{redis, Pool as RedisPool};

use crate::crypto::pow_difficulty::{self, DifficultyState};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PressureSeverity {
    Normal,
    Warn,
    High,
    Critical,
}

impl PressureSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warn => "warn",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn is_elevated(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

fn classify(state: &DifficultyState) -> PressureSeverity {
    if state.final_difficulty >= 31
        || state.suspicion_bonus >= 3
        || state.recent_registrations > 300
        || state.recent_challenges > 3_000
    {
        PressureSeverity::Critical
    } else if state.final_difficulty >= 29
        || state.suspicion_bonus >= 2
        || state.recent_registrations > 100
        || state.recent_challenges > 1_000
    {
        PressureSeverity::High
    } else if state.final_difficulty > 22
        || state.suspicion_bonus > 0
        || state.recent_registrations > 5
        || state.recent_challenges > 30
    {
        PressureSeverity::Warn
    } else {
        PressureSeverity::Normal
    }
}

fn pressure_signature(state: &DifficultyState, severity: PressureSeverity) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        severity.as_str(),
        state.final_difficulty,
        state.registration_difficulty,
        state.challenge_difficulty,
        state.suspicion_bonus
    )
}

async fn pressure_state_changed(redis: &RedisPool, signature: &str) -> anyhow::Result<bool> {
    let mut conn = redis.get().await?;
    let previous: Option<String> = redis::cmd("GET")
        .arg("reg:difficulty_manager:last_log")
        .query_async(&mut conn)
        .await?;
    if previous.as_deref() == Some(signature) {
        return Ok(false);
    }
    let _: () = redis::cmd("SET")
        .arg("reg:difficulty_manager:last_log")
        .arg(signature)
        .arg("EX")
        .arg(3600)
        .query_async(&mut conn)
        .await?;
    Ok(true)
}

fn log_pressure(state: &DifficultyState, severity: PressureSeverity) {
    match severity {
        PressureSeverity::Critical => tracing::error!(
            event = "registration_pressure",
            severity = severity.as_str(),
            difficulty = state.final_difficulty,
            base = state.base_difficulty,
            registration_base = state.registration_difficulty,
            challenge_base = state.challenge_difficulty,
            suspicion_bonus = state.suspicion_bonus,
            suspicion = state.suspicion,
            recent_registrations = state.recent_registrations,
            recent_challenges = state.recent_challenges,
        ),
        PressureSeverity::High => tracing::error!(
            event = "registration_pressure",
            severity = severity.as_str(),
            difficulty = state.final_difficulty,
            base = state.base_difficulty,
            registration_base = state.registration_difficulty,
            challenge_base = state.challenge_difficulty,
            suspicion_bonus = state.suspicion_bonus,
            suspicion = state.suspicion,
            recent_registrations = state.recent_registrations,
            recent_challenges = state.recent_challenges,
        ),
        PressureSeverity::Warn => tracing::warn!(
            event = "registration_pressure",
            severity = severity.as_str(),
            difficulty = state.final_difficulty,
            base = state.base_difficulty,
            registration_base = state.registration_difficulty,
            challenge_base = state.challenge_difficulty,
            suspicion_bonus = state.suspicion_bonus,
            suspicion = state.suspicion,
            recent_registrations = state.recent_registrations,
            recent_challenges = state.recent_challenges,
        ),
        PressureSeverity::Normal => {}
    }
}

pub async fn run(redis: RedisPool) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut redis_error_reported = false;
    let mut local_signature = String::new();

    loop {
        interval.tick().await;

        match pow_difficulty::try_acquire_manager_tick(&redis).await {
            Ok(true) => redis_error_reported = false,
            Ok(false) => continue,
            Err(_) => {
                if !redis_error_reported {
                    tracing::error!(
                        event = "difficulty_manager_redis_unavailable",
                        severity = "critical"
                    );
                    redis_error_reported = true;
                }
                continue;
            }
        }

        let mut state = match pow_difficulty::compute_difficulty(&redis).await {
            Ok(state) => state,
            Err(_) => {
                tracing::error!(
                    event = "difficulty_manager_redis_unavailable",
                    severity = "critical"
                );
                redis_error_reported = true;
                continue;
            }
        };

        if state.recent_registrations < 5 && state.suspicion > 0 {
            let _ = pow_difficulty::decrement_suspicion(&redis).await;
            if let Ok(updated) = pow_difficulty::compute_difficulty(&redis).await {
                state = updated;
            }
        }

        let severity = classify(&state);
        let signature = pressure_signature(&state, severity);
        let changed = pressure_state_changed(&redis, &signature)
            .await
            .unwrap_or_else(|_| {
                let changed = local_signature != signature;
                if changed {
                    local_signature = signature.clone();
                }
                changed
            });

        if changed && severity.is_elevated() {
            log_pressure(&state, severity);
        }
    }
}
