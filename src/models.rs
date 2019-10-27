use chrono::{DateTime, Utc};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub struct Machine {
    pub hostname: String,
    pub wireguard_ip: Option<Ipv4Addr>,
    pub wireguard_port: Option<i32>,
    pub wireguard_privkey: Option<String>,
    pub wireguard_pubkey: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub added_time: DateTime<Utc>,
    pub owner: String,
    pub provider_id: Option<i32>,
    pub provider_reference: Option<String>,
    pub networks: Vec<String>,
    pub addresses: Vec<MachineAddress>,
}

#[derive(Debug)]
pub struct MachineAddress {
    pub hostname: String,
    pub network: String,
    pub address: IpAddr,
    pub ssh_port: Option<i32>,
    pub wireguard_port: Option<i32>,
}

#[derive(Debug)]
pub struct WireguardKeepalive {
    pub source_machine: String,
    pub target_machine: String,
    pub interval_sec: i32,
}

#[derive(Debug)]
pub struct Network {
    pub name: String,
}

#[derive(Debug)]
pub struct NetworkLink {
    pub name: String,
    pub other_network: String,
    pub priority: i32,
}

#[derive(Debug)]
pub struct Provider {
    pub id: i32,
    pub name: String,
    pub email: String,
}
