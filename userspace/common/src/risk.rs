//! Phase 13 risk engine.
//!
//! Fuses the detector and model outputs for one entity (a source or service)
//! into a single risk, maps it onto a mitigation ladder, and decides an action
//! with the guard rails that keep automatic mitigation safe:
//!
//!   * **evidence fusion** by noisy-OR: independent signals (statistical
//!     anomaly, DDoS classifier, bot detector, deterministic rule) combine as
//!     `1 - Π(1 - w_i · s_i)`, so agreeing signals reinforce but no single one
//!     runs away;
//!   * **ladder + hysteresis**: escalation needs the risk sustained above a
//!     level for `escalate_windows`, de-escalation needs it below for
//!     `deescalate_windows`, so a flapping signal cannot flap the action;
//!   * **TTL**: every applied action expires, so mitigation is self-healing;
//!   * **guard rails**: allowlisted / known-good entities never leave `Pass`,
//!     a per-window escalation budget bounds blast radius, and a circuit
//!     breaker trips when too many entities escalate at once (likely a false
//!     global signal), forcing shadow-only until it resets;
//!   * **shadow mode**: decisions are computed and logged but not applied.

use std::collections::HashMap;

/// Mitigation ladder, least to most aggressive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    #[default]
    Pass = 0,
    Monitor = 1,
    Sample = 2,
    RateLimit = 3,
    AggressiveRateLimit = 4,
    TemporaryBlock = 5,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Pass => "pass",
            Level::Monitor => "monitor",
            Level::Sample => "sample",
            Level::RateLimit => "rate_limit",
            Level::AggressiveRateLimit => "aggressive_rate_limit",
            Level::TemporaryBlock => "temporary_block",
        }
    }
    fn from_usize(n: usize) -> Level {
        match n {
            0 => Level::Pass,
            1 => Level::Monitor,
            2 => Level::Sample,
            3 => Level::RateLimit,
            4 => Level::AggressiveRateLimit,
            _ => Level::TemporaryBlock,
        }
    }
    /// The level a given risk maps to (before hysteresis).
    fn target(risk: f64) -> Level {
        match risk {
            r if r >= 0.95 => Level::TemporaryBlock,
            r if r >= 0.85 => Level::AggressiveRateLimit,
            r if r >= 0.70 => Level::RateLimit,
            r if r >= 0.50 => Level::Sample,
            r if r >= 0.30 => Level::Monitor,
            _ => Level::Pass,
        }
    }
}

/// The evidence for one entity in one window. Each score is in `[0, 1]`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Evidence {
    pub anomaly: f64,
    pub ddos: f64,
    pub bot: f64,
    /// 1.0 if a deterministic rule named an attack, else 0.
    pub rule: f64,
    /// Sample coverage / model confidence in `[0, 1]`; discounts weak evidence.
    pub confidence: f64,
}

/// Fuse evidence into a single risk in `[0, 1]` by weighted noisy-OR.
pub fn fuse(e: &Evidence) -> f64 {
    // Per-signal trust weights (rules and the DDoS classifier are the most
    // decisive; the anomaly model is broad but noisier).
    let conf = if e.confidence <= 0.0 { 1.0 } else { e.confidence.clamp(0.0, 1.0) };
    let terms = [(e.anomaly, 0.6), (e.ddos, 0.95), (e.bot, 0.8), (e.rule, 0.9)];
    let mut prod = 1.0;
    for (s, w) in terms {
        let s = s.clamp(0.0, 1.0) * conf;
        prod *= 1.0 - w * s;
    }
    1.0 - prod
}

/// Tunables for the engine.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub escalate_windows: u32,
    pub deescalate_windows: u32,
    pub ttl_s: u64,
    /// Max entities that may be escalated per window (blast-radius budget).
    pub escalation_budget: usize,
    /// If more than this many entities want to escalate in one window, trip the
    /// circuit breaker (probable false global signal) and go shadow-only.
    pub breaker_threshold: usize,
    /// Windows the breaker stays tripped once triggered.
    pub breaker_cooldown: u32,
    pub shadow: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            escalate_windows: 3,
            deescalate_windows: 5,
            ttl_s: 600,
            escalation_budget: 64,
            breaker_threshold: 256,
            breaker_cooldown: 10,
            shadow: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct EntityState {
    level: Level,
    above: u32, // consecutive windows the target exceeds the current level
    below: u32, // consecutive windows the target is under the current level
    expires_at: u64,
}


/// One decision for one entity in one window.
#[derive(Clone, Debug)]
pub struct Decision {
    pub entity: String,
    pub risk: f64,
    pub level: Level,
    pub previous: Level,
    pub applied: bool,
    pub ttl_s: u64,
    pub reason: String,
}

/// The risk engine: per-entity ladder state plus global guard rails.
#[derive(Debug)]
pub struct RiskEngine {
    cfg: Config,
    entities: HashMap<String, EntityState>,
    breaker_ticks: u32,
    escalations_this_window: usize,
}

impl RiskEngine {
    pub fn new(cfg: Config) -> Self {
        RiskEngine { cfg, entities: HashMap::new(), breaker_ticks: 0, escalations_this_window: 0 }
    }

    /// Whether the circuit breaker is currently tripped.
    pub fn breaker_tripped(&self) -> bool {
        self.breaker_ticks > 0
    }

    /// Call once per window before per-entity `decide` calls, so the breaker
    /// and the per-window escalation budget reset correctly.
    pub fn begin_window(&mut self, wanting_escalation: usize) {
        self.escalations_this_window = 0;
        if self.breaker_ticks > 0 {
            self.breaker_ticks -= 1;
        }
        if wanting_escalation > self.cfg.breaker_threshold {
            self.breaker_ticks = self.cfg.breaker_cooldown;
        }
    }

    /// Decide the action for one entity this window.
    /// `allowlisted` entities never leave `Pass`. `now_s` is monotonic seconds.
    pub fn decide(
        &mut self,
        entity: &str,
        ev: &Evidence,
        allowlisted: bool,
        now_s: u64,
    ) -> Decision {
        let risk = fuse(ev);
        let st = self.entities.entry(entity.to_string()).or_default();
        let previous = st.level;

        // Guard rail: allowlisted / known-good entities are never mitigated.
        if allowlisted {
            st.level = Level::Pass;
            st.above = 0;
            st.below = 0;
            return Decision {
                entity: entity.into(),
                risk,
                level: Level::Pass,
                previous,
                applied: false,
                ttl_s: 0,
                reason: "allowlisted: guard rail holds at pass".into(),
            };
        }

        // Expire an action whose TTL lapsed -> drop one rung.
        if st.level > Level::Pass && st.expires_at != 0 && now_s >= st.expires_at {
            st.level = Level::from_usize(st.level as usize - 1);
            st.above = 0;
            st.below = 0;
        }

        let target = Level::target(risk);

        // Hysteresis counters.
        if target > st.level {
            st.above += 1;
            st.below = 0;
        } else if target < st.level {
            st.below += 1;
            st.above = 0;
        } else {
            st.above = 0;
            st.below = 0;
        }

        let mut reason = format!("risk {risk:.2} -> target {}", target.as_str());
        let mut want_escalate = false;

        if st.above >= self.cfg.escalate_windows && st.level < Level::TemporaryBlock {
            want_escalate = true;
        } else if st.below >= self.cfg.deescalate_windows && st.level > Level::Pass {
            st.level = Level::from_usize(st.level as usize - 1);
            st.below = 0;
            reason = format!("{reason}; de-escalated after cooldown");
        }

        // Escalation is gated by the budget and the circuit breaker.
        if want_escalate {
            if self.breaker_ticks > 0 {
                reason = format!("{reason}; escalation suppressed: circuit breaker");
            } else if self.escalations_this_window >= self.cfg.escalation_budget {
                reason = format!("{reason}; escalation deferred: budget exhausted");
            } else {
                // Jump straight to the risk's target rung instead of climbing one
                // rung per escalation. Climbing one-at-a-time meant a clear flood
                // (which maps directly to the top of the ladder) took ~5 escalations
                // to reach level 5 where DROP_UDP_STRICT and the hard aggregate cap
                // arm -- ~10s, and at multi-Mpps that let ~100M packets through
                // before mitigation was fully effective. Hysteresis (escalate_windows)
                // still gates WHEN we move and the budget/breaker/allowlist guard
                // rails are unchanged; this only changes HOW FAR per move. target is
                // always > st.level here, and the max() keeps it a strict climb.
                st.level = target.max(Level::from_usize(st.level as usize + 1));
                st.above = 0;
                self.escalations_this_window += 1;
                reason = format!("{reason}; escalated to {}", st.level.as_str());
            }
        }

        if st.level > Level::Pass {
            st.expires_at = now_s + self.cfg.ttl_s;
        } else {
            st.expires_at = 0;
        }

        let level = st.level;
        let ttl = if level > Level::Pass { self.cfg.ttl_s } else { 0 };
        let applied = !self.cfg.shadow && !(self.breaker_tripped() && level > previous);
        if self.cfg.shadow {
            reason = format!("{reason}; shadow mode (not applied)");
        }
        Decision { entity: entity.into(), risk, level, previous, applied, ttl_s: ttl, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attack_ev() -> Evidence {
        Evidence { anomaly: 0.9, ddos: 0.98, bot: 0.2, rule: 1.0, confidence: 1.0 }
    }
    fn calm_ev() -> Evidence {
        Evidence { anomaly: 0.02, ddos: 0.0, bot: 0.0, rule: 0.0, confidence: 1.0 }
    }

    #[test]
    fn fusion_bounds_and_reinforcement() {
        assert!((fuse(&calm_ev())).abs() < 0.05);
        let r = fuse(&attack_ev());
        assert!(r > 0.95, "risk {r}");
        // low confidence discounts the evidence
        let mut weak = attack_ev();
        weak.confidence = 0.1;
        assert!(fuse(&weak) < r);
    }

    #[test]
    fn sustained_attack_escalates_to_block() {
        let mut e = RiskEngine::new(Config::default());
        let ev = attack_ev();
        let mut level = Level::Pass;
        for w in 0..40u64 {
            e.begin_window(1);
            level = e.decide("1.2.3.4", &ev, false, w).level;
        }
        assert_eq!(level, Level::TemporaryBlock, "reached {level:?}");
    }

    #[test]
    fn clear_flood_jumps_to_top_rung_fast() {
        // A clear, sustained flood maps to the top of the ladder and must reach
        // it within ~escalate_windows, not after climbing every rung (which used
        // to take ~5x longer and leaked packets before DROP_UDP_STRICT armed).
        let mut cfg = Config::default();
        cfg.escalate_windows = 2;
        let mut e = RiskEngine::new(cfg);
        let ev = attack_ev();
        let mut reached_at = None;
        for w in 0..6u64 {
            e.begin_window(1);
            if e.decide("svc", &ev, false, w).level == Level::TemporaryBlock {
                reached_at = Some(w);
                break;
            }
        }
        assert!(matches!(reached_at, Some(w) if w <= 2), "reached top at window {reached_at:?}");
    }

    #[test]
    fn flapping_does_not_flap_actions() {
        // Alternate attack/calm every window. Hysteresis (escalate=3, de-esc=5)
        // means it should not oscillate the action every window.
        let mut e = RiskEngine::new(Config::default());
        let mut changes = 0;
        let mut prev = Level::Pass;
        for w in 0..40u64 {
            e.begin_window(1);
            let ev = if w % 2 == 0 { attack_ev() } else { calm_ev() };
            let d = e.decide("x", &ev, false, w);
            if d.level != prev {
                changes += 1;
                prev = d.level;
            }
        }
        // Without hysteresis this would change ~40 times; require it be small.
        assert!(changes <= 3, "action changed {changes} times");
    }

    #[test]
    fn allowlist_guard_rail() {
        let mut e = RiskEngine::new(Config::default());
        let ev = attack_ev();
        for w in 0..20u64 {
            e.begin_window(1);
            let d = e.decide("10.0.0.1", &ev, true, w);
            assert_eq!(d.level, Level::Pass);
            assert!(!d.applied);
        }
    }

    #[test]
    fn circuit_breaker_suppresses_mass_escalation() {
        let mut cfg = Config::default();
        cfg.breaker_threshold = 10;
        cfg.escalate_windows = 1;
        let mut e = RiskEngine::new(cfg);
        let ev = attack_ev();
        // 100 entities all want to escalate -> breaker trips.
        for w in 0..3u64 {
            e.begin_window(100);
            for i in 0..100 {
                e.decide(&format!("src{i}"), &ev, false, w);
            }
        }
        assert!(e.breaker_tripped());
    }

    #[test]
    fn escalation_budget_bounds_blast_radius() {
        let mut cfg = Config::default();
        cfg.escalate_windows = 1;
        cfg.escalation_budget = 5;
        cfg.breaker_threshold = 100000;
        let mut e = RiskEngine::new(cfg);
        let ev = attack_ev();
        e.begin_window(50);
        let mut escalated = 0;
        for i in 0..50 {
            // fresh entities: 3 above-windows needed normally, but escalate_windows=1
            if e.decide(&format!("s{i}"), &ev, false, 0).level > Level::Pass {
                escalated += 1;
            }
        }
        assert!(escalated <= 5, "escalated {escalated} > budget");
    }

    #[test]
    fn shadow_mode_does_not_apply() {
        let mut cfg = Config::default();
        cfg.shadow = true;
        cfg.escalate_windows = 1;
        let mut e = RiskEngine::new(cfg);
        let ev = attack_ev();
        e.begin_window(1);
        let d = e.decide("s", &ev, false, 0);
        assert!(!d.applied);
        assert!(d.reason.contains("shadow"));
    }

    #[test]
    fn ttl_self_heals() {
        let mut cfg = Config::default();
        cfg.escalate_windows = 1;
        cfg.ttl_s = 5;
        let mut e = RiskEngine::new(cfg);
        // escalate once
        e.begin_window(1);
        let up = e.decide("s", &attack_ev(), false, 0);
        assert!(up.level > Level::Pass);
        // then go calm and let TTL + de-escalation heal back to pass
        let mut level = up.level;
        for w in 1..60u64 {
            e.begin_window(0);
            level = e.decide("s", &calm_ev(), false, w).level;
        }
        assert_eq!(level, Level::Pass);
    }
}
