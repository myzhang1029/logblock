use const_format::concatcp;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

mod attack;
mod journal;
mod nft;

const IP_PATTERN: &str = r"[0-9\.:a-fA-F]+";
const SSHD_PATTERN: &str = concatcp!(
    r"(Connection closed by authenticating user|Invalid user|Failed password for( invalid user)?) \S+( from)? (",
    IP_PATTERN,
    r") (port \d+ )?"
);

const LIMIT_ATTEMPTS: u32 = 4;
const ATTEMPT_WINDOW: Duration = Duration::from_mins(60);
const UNLOCK_TIME: Duration = Duration::from_mins(5);
const CHECK_UNLOCK_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut filters = HashMap::new();
    filters.insert(
        "ssh.service".to_string(),
        (regex::Regex::new(SSHD_PATTERN).unwrap(), 4),
    );
    filters.insert(
        "sshd.service".to_string(),
        (regex::Regex::new(SSHD_PATTERN).unwrap(), 4),
    );
    let mut streamer = journal::JournalFailureStreamer::new(filters).unwrap();
    let mut attackers = HashMap::new();
    let mut last_unlock_check = SystemTime::now();

    nft::init_tables()?;

    loop {
        if let Some(attack_ip) = streamer.next_match(Some(CHECK_UNLOCK_INTERVAL))? {
            log::info!("Got attacker: {attack_ip}");
            let attacker_info = attackers
                .entry(attack_ip)
                .or_insert_with(|| attack::AttackerInfo::new(None));
            log::debug!("attacker info: {attacker_info:?}");
            let now = SystemTime::now();
            let cutoff = now
                .checked_sub(ATTEMPT_WINDOW)
                .expect("Ran out of representable time");
            attacker_info.evict_old_attempts(cutoff);
            let attempts = attacker_info.record_attempt();
            if attempts >= LIMIT_ATTEMPTS {
                log::info!("Blocking IP {attack_ip} after {attempts} attempts");
                nft::block_ip(attack_ip)?;
            }
        }

        // After processing, or timing out, check for unlocks
        let now = SystemTime::now();
        if now
            .duration_since(last_unlock_check)
            .expect("Time went backwards")
            >= CHECK_UNLOCK_INTERVAL
        {
            log::debug!("checking for IPs to unlock");
            let unlock_cutoff = now
                .checked_sub(UNLOCK_TIME)
                .expect("Ran out of representable time");
            for (ip, info) in &attackers {
                if info.last_seen < unlock_cutoff && info.attempts > LIMIT_ATTEMPTS {
                    log::info!("Unblocking IP {ip} last seen at {:?}", info.last_seen);
                    nft::unblock_ip(*ip).unwrap_or_else(|e| {
                        log::warn!("Failed to unblock IP {ip}: {e}");
                    });
                }
            }
            last_unlock_check = now;
        }
    }
}
