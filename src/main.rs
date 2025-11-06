use const_format::concatcp;
use std::{collections::HashMap, time::SystemTime};

mod attack;
mod journal;
mod nft;

const IP_PATTERN: &str = r"[0-9\.:a-fA-F]+";
const SSHD_PATTERN: &str = concatcp!(
    r"(Connection closed by authenticating user|Failed password for( invalid user)?) \S+( from)? (",
    IP_PATTERN,
    r") (port \d+ )?"
);

const LIMIT_ATTEMPTS: u32 = 5;
const ATTEMPT_WINDOW_SECS: u64 = 300;
const UNLOCK_TIME_SECS: u64 = 600;
const CHECK_UNLOCK_INTERVAL_SECS: u64 = 60;

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
        let attack_ip = streamer.next().expect("Streamer should never end")?;
        log::info!("Got attack IP: {attack_ip:?}");
        let attacker_info = attackers
            .entry(attack_ip)
            .or_insert_with(|| attack::AttackerInfo::new(None));
        log::debug!("attacker info: {attacker_info:?}");
        let now = SystemTime::now();
        let cutoff = now
            .checked_sub(std::time::Duration::new(ATTEMPT_WINDOW_SECS, 0))
            .expect("Ran out of representable time");
        attacker_info.evict_old_attempts(cutoff);
        let attempts = attacker_info.record_attempt();
        if attempts > LIMIT_ATTEMPTS {
            log::info!("Blocking IP {attack_ip} after {attempts} attempts");
            nft::block_ip(attack_ip)?;
        }
        if now
            .duration_since(last_unlock_check)
            .expect("Time went backwards")
            .as_secs()
            >= CHECK_UNLOCK_INTERVAL_SECS
        {
            log::debug!("checking for IPs to unlock");
            let unlock_cutoff = now
                .checked_sub(std::time::Duration::new(UNLOCK_TIME_SECS, 0))
                .expect("Ran out of representable time");
            for (ip, info) in &attackers {
                if info.last_seen < unlock_cutoff && info.attempts > LIMIT_ATTEMPTS {
                    log::info!("Unblocking IP {ip} last seen at {:?}", info.last_seen);
                    nft::unblock_ip(*ip)?;
                }
            }
            last_unlock_check = now;
        }
    }
}
