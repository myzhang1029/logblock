/// Stuff about attackers
use std::time::Instant;

/// An attacker
#[derive(Copy, Clone, Debug)]
pub struct AttackerInfo {
    /// Number of failed attempts
    pub attempts: u32,
    /// Last seen timestamp
    pub last_seen: Instant,
}

impl AttackerInfo {
    /// Return a new attacker
    pub fn new(timestamp: Option<Instant>) -> Self {
        let now = Instant::now();
        Self {
            attempts: 0,
            last_seen: timestamp.unwrap_or(now),
        }
    }

    /// Record a new failed attempt
    pub fn record_attempt(&mut self) -> u32 {
        self.attempts += 1;
        self.last_seen = Instant::now();
        self.attempts
    }

    /// Evict old attempts
    pub fn evict_old_attempts(&mut self, cutoff: Instant) {
        if self.last_seen < cutoff {
            self.attempts = 0;
        }
    }
}
