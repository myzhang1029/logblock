use const_format::concatcp;
use std::collections::HashMap;

mod journal;

const IP_PATTERN: &str = r"[0-9\.:a-fA-F]+";
const SSHD_PATTERN: &str = concatcp!(
    r"(Connection closed by authenticating user|Failed password for( invalid user)?) \S+( from)? (",
    IP_PATTERN,
    r") (port \d+ )?"
);
fn main() {
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

    loop {
        println!("{:?}", streamer.next());
    }
}
