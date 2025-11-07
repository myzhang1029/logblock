use const_format::concatcp;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
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
    let mut last_unlock_check = Instant::now();

    nft::init_tables()?;

    loop {
        if let Some(attack_ip) = streamer.next_match(Some(CHECK_UNLOCK_INTERVAL))? {
            log::info!("Got attacker: {attack_ip}");
            let attacker_info = attackers
                .entry(attack_ip)
                .or_insert_with(|| attack::AttackerInfo::new(None));
            log::debug!("attacker info: {attacker_info:?}");
            let now = Instant::now();
            let cutoff = now
                .checked_sub(ATTEMPT_WINDOW)
                .expect("Ran out of representable time");
            attacker_info.evict_old_attempts(cutoff);
            let attempts = attacker_info.record_attempt();
            if attempts != 0 && attempts % LIMIT_ATTEMPTS == 0 {
                log::info!("Blocking IP {attack_ip} after {attempts} attempts");
                block_ip_or_reinit_tables(attack_ip, &attackers)?;
            }
        }

        // After processing, or timing out, check for unlocks
        if last_unlock_check.elapsed() >= CHECK_UNLOCK_INTERVAL {
            log::debug!("checking for IPs to unlock");
            check_and_unblock_ips(&attackers);
            last_unlock_check = Instant::now();
        }
    }
}

/// Calculate when an attacker can be unblocked
/// Returns `None` if the attacker should not be blocked
/// Returns `Some(Instant)` indicating when the attacker can be unblocked
fn evaluate_attacker_unblock_time(info: &attack::AttackerInfo) -> Option<Instant> {
    let attacker_level = info.attempts / LIMIT_ATTEMPTS;
    if attacker_level == 0 {
        return None;
    }
    // `unwrap`: checked above that attacker_level > 0
    let attacker_unlock_duration =
        UNLOCK_TIME.saturating_mul(1 << (attacker_level.checked_sub(1).unwrap()));
    let cutoff = info
        .last_seen
        .checked_add(attacker_unlock_duration)
        .expect("Ran out of representable time");
    Some(cutoff)
}

/// Unblock all IPs that are eligible for unblocking
fn check_and_unblock_ips(attackers: &HashMap<IpAddr, attack::AttackerInfo>) {
    let now = Instant::now();
    for (ip, info) in attackers {
        let Some(cutoff) = evaluate_attacker_unblock_time(info) else {
            continue;
        };
        if now >= cutoff {
            log::info!("Unblocking IP {ip} last seen at {:?}", info.last_seen);
            nft::unblock_ip(*ip).unwrap_or_else(|e| {
                log::warn!("Failed to unblock IP {ip}: {e}");
            });
        }
    }
}

/// Restore blocks for all attackers that should still be blocked
fn restore_blocked_ips(attackers: &HashMap<IpAddr, attack::AttackerInfo>) -> anyhow::Result<()> {
    let now = Instant::now();
    for (ip, info) in attackers {
        let Some(cutoff) = evaluate_attacker_unblock_time(info) else {
            continue;
        };
        if now < cutoff {
            log::info!(
                "Restoring block for IP {ip} last seen at {:?}",
                info.last_seen
            );
            nft::block_ip(*ip)?;
        }
    }
    Ok(())
}

/// Try to block an IP, and if it fails due to nftables error, reinitialize tables and try again
fn block_ip_or_reinit_tables(
    ip: IpAddr,
    attackers: &HashMap<IpAddr, attack::AttackerInfo>,
) -> anyhow::Result<()> {
    let Err(e) = nft::block_ip(ip) else {
        return Ok(());
    };
    if let nftables::helper::NftablesError::NftFailed { hint, .. } = &e
        && hint == "applying ruleset"
    {
        log::warn!("Got nftables error: {e}, reinitializing tables");
        nft::init_tables()?;
        restore_blocked_ips(attackers)?;
        nft::block_ip(ip)?;
        Ok(())
    } else {
        Err(e.into())
    }
}
