use ipnetwork::IpNetwork;
use chrono::{DateTime, Utc};

#[derive(Queryable, Debug)]
pub struct Machine {
    pub hostname: String,
    pub wireguard_ip: Option<IpNetwork>,
    pub wireguard_port: Option<i32>,
    pub wireguard_pubkey: Option<String>,
    pub ssh_port: i32,
    pub ssh_user: String,
    pub added_time: DateTime<Utc>,
}
