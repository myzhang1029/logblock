use std::{collections::HashMap, net::IpAddr};

use regex::Regex;
use systemd::journal::{self, Journal, JournalSeek};

pub struct JournalFailureStreamer {
    journal: Journal,
    filter: HashMap<String, Regex>,
}

impl JournalFailureStreamer {
    /// Create a new systemd journal streamer with the given filters
    pub fn new(filter: HashMap<String, Regex>) -> anyhow::Result<Self> {
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

    /// Get the next log line from the journal that matches the filters
    pub fn next_line(&mut self) -> anyhow::Result<(String, String)> {
        loop {
            while let Some(entry) = self.journal.next_entry()? {
                let Some(unit) = entry.get("_SYSTEMD_UNIT") else {
                    continue;
                };
                let Some(message) = entry.get("MESSAGE") else {
                    continue;
                };
                log::trace!("journal entry MESSAGE={message} UNIT={unit}",);
                return Ok((unit.clone(), message.clone()));
            }
            self.journal.wait(None)?;
        }
    }

    fn ip_from_msg(&self, unit: &str, msg: &str) -> Option<IpAddr> {
        let regex = self.filter.get(unit)?;
        let caps = regex.captures(msg)?;
        let ip_str = caps.get(1)?.as_str();
        log::debug!("extracted IP address string: {ip_str}");
        ip_str.parse().ok()
    }
}

impl Iterator for JournalFailureStreamer {
    type Item = anyhow::Result<IpAddr>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok((unit, msg)) = self.next_line() {
            let Some(ip) = self.ip_from_msg(&unit, &msg) else {
                log::debug!("no IP found in message: {msg}");
                continue;
            };
            return Some(Ok(ip));
        }
        None
    }
}
