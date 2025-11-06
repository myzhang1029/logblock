use std::{collections::HashMap, net::IpAddr, time::Duration};

use regex::Regex;
use systemd::journal::{self, Journal, JournalSeek};

/// Stream IPs from journal failure entries
pub struct JournalFailureStreamer {
    /// The systemd journal instance
    journal: Journal,
    /// unit -> (regex to extract IP, match group index)
    filter: HashMap<String, (Regex, usize)>,
}

impl JournalFailureStreamer {
    /// Create a new systemd journal streamer with the given filters
    pub fn new(filter: HashMap<String, (Regex, usize)>) -> anyhow::Result<Self> {
        let units_of_interest: Vec<&str> = filter.keys().map(String::as_str).collect();
        let mut journal = journal::OpenOptions::default().system(true).open()?;
        // Go to the end of the journal and step back one entry
        journal.seek(JournalSeek::Tail)?;
        journal.previous()?;
        // Apply filters to the journal
        for unit in &units_of_interest {
            log::info!("Filter OR for unit {unit}");
            journal.match_add("_SYSTEMD_UNIT", *unit)?;
            journal.match_or()?;
        }
        Ok(Self { journal, filter })
    }

    fn ip_from_msg(&self, unit: &str, msg: &str) -> Option<IpAddr> {
        let (regex, group_idx) = self.filter.get(unit)?;
        let caps = regex.captures(msg);
        log::trace!("regex captures got: {caps:?}");
        let ip_str = caps?.get(*group_idx)?.as_str();
        log::debug!("extracted IP address string: {ip_str}");
        ip_str.parse().ok()
    }

    /// Get the next matching IP address from the journal
    /// This iterator should never end
    pub fn next_match(
        &mut self,
        mut wait_limit: Option<Duration>,
    ) -> anyhow::Result<Option<IpAddr>> {
        let begin = std::time::Instant::now();
        loop {
            // Recompute remaining wait limit for this iteration
            // If overflow occurs, peg to zero
            wait_limit = wait_limit.map(|limit| limit.saturating_sub(begin.elapsed()));
            let Some(entry) = self.journal.await_next_entry(wait_limit)? else {
                // `await_next_entry` timed out
                return Ok(None);
            };
            let Some(unit) = entry.get("_SYSTEMD_UNIT") else {
                continue;
            };
            let Some(message) = entry.get("MESSAGE") else {
                continue;
            };
            log::trace!("journal entry match MESSAGE={message} UNIT={unit}");
            let Some(ip) = self.ip_from_msg(unit, message) else {
                log::debug!("no IP found in message: {message}");
                continue;
            };
            return Ok(Some(ip));
        }
    }
}
