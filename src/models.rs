use ipnetwork::IpNetwork;
use chrono::{DateTime, Utc};
use crate::schema::{machines, machine_addresses, networks};

#[derive(Identifiable, Queryable, Debug)]
#[primary_key(hostname)]
#[table_name = "machines"]
pub struct Machine {
    pub hostname: String,
    pub wireguard_ip: Option<IpNetwork>,
    pub wireguard_port: Option<i32>,
    pub wireguard_pubkey: Option<String>,
    pub ssh_port: i32,
    pub ssh_user: String,
    pub added_time: DateTime<Utc>,
}

#[derive(Identifiable, Queryable, Associations, Debug)]
#[primary_key(hostname, network, address)]
#[belongs_to(Machine, foreign_key = "hostname")]
#[table_name = "machine_addresses"]
pub struct MachineAddress {
    pub hostname: String,
    pub network: String,
    pub address: IpNetwork,
}

#[derive(Identifiable, Queryable, Debug)]
#[primary_key(name)]
#[table_name = "networks"]
pub struct Network {
    pub name: String,
    pub parent: String,
}
