use ipnetwork::IpNetwork;
use chrono::{DateTime, Utc};
use crate::schema::*;

#[derive(Identifiable, Queryable, Debug)]
#[primary_key(hostname)]
#[table_name = "machines"]
pub struct Machine {
    pub hostname: String,
    pub wireguard_ip: Option<IpNetwork>,
    pub wireguard_port: Option<i32>,
    pub wireguard_privkey: Option<String>,
    pub wireguard_pubkey: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub added_time: DateTime<Utc>,
    pub owner: String,
    pub provider_id: Option<i32>,
    pub provider_reference: Option<String>,
}

#[derive(Insertable, Debug)]
#[table_name = "machines"]
pub struct NewMachine {
    pub hostname: String,
    pub wireguard_ip: Option<IpNetwork>,
    pub wireguard_port: Option<i32>,
    pub wireguard_privkey: Option<String>,
    pub wireguard_pubkey: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub owner: String,
    pub provider_id: Option<i32>,
    pub provider_reference: Option<String>,
}

#[derive(Identifiable, Insertable, Queryable, Associations, Debug)]
#[primary_key(hostname, network, address)]
#[belongs_to(Machine, foreign_key = "hostname")]
#[table_name = "machine_addresses"]
pub struct MachineAddress {
    pub hostname: String,
    pub network: String,
    pub address: IpNetwork,
    pub ssh_port: Option<i32>,
    pub wireguard_port: Option<i32>,
}

#[derive(Identifiable, Insertable, Queryable, Associations, Debug)]
#[primary_key(source_machine, target_machine)]
#[belongs_to(Machine, foreign_key = "source_machine")]
#[table_name = "wireguard_keepalives"]
pub struct WireguardKeepalive {
    pub source_machine: String,
    pub target_machine: String,
    pub interval_sec: i32,
}

#[derive(Identifiable, Queryable, Debug)]
#[primary_key(name)]
#[table_name = "networks"]
pub struct Network {
    pub name: String,
}

#[derive(Identifiable, Queryable, Debug)]
#[primary_key(name, other_network, priority)]
#[table_name = "networks"]
pub struct NetworkLink {
    pub name: String,
    pub other_network: String,
    pub priority: i32,
}

#[derive(Identifiable, Queryable, Debug)]
#[table_name = "providers"]
pub struct Provider {
    pub id: i32,
    pub name: String,
    pub email: String,
}
