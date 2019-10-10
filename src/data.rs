use std::collections::HashMap;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::sync::Arc;
use std::fmt::{Debug, Formatter};
use natural_sort::HumanStr;

use crate::schema::{machines, machine_addresses, providers, wireguard_keepalives};
use crate::models::{Machine, MachineAddress, Provider, NetworkLink, WireguardKeepalive};

pub(crate) type DieselResult<T> = Result<T, diesel::result::Error>;

/// A map of (network, other_network) -> priority
pub(crate) type NetworkLinksPriorityMap = HashMap<(String, String), i32>;

/// A map of (source_machine, target_machine) -> interval
pub(crate) type WireguardKeepaliveIntervalMap = HashMap<(String, String), i32>;

pub(crate) type MachinesAndAddresses = Vec<(Machine, Vec<MachineAddress>)>;

struct PgConnectionWrapper {
    connection: PgConnection
}

impl Debug for PgConnectionWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("PgConnectionWrapper")
    }
}

fn sort_machines_and_addresses(data: &mut MachinesAndAddresses) {
    // natural_sort refuses to compare string segments with integer segments,
    // so if returns None, fall back to String cmp.
    data.sort_unstable_by(|(m1, _), (m2, _)| {
        HumanStr::new(&m1.hostname)
            .partial_cmp(&HumanStr::new(&m2.hostname))
            .unwrap_or_else(|| m1.hostname.cmp(&m2.hostname))
    });
}

fn sort_addresses(data: &mut Addresses) {
    // natural_sort refuses to compare string segments with integer segments,
    // so if returns None, fall back to String cmp.
    addresses.sort_unstable_by(|a1, a2| {
        HumanStr::new(&a1.hostname)
            .partial_cmp(&HumanStr::new(&a2.hostname))
            .unwrap_or_else(|| a1.hostname.cmp(&a2.hostname))
    });
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AllData {
    machines_and_addresses: MachinesAndAddresses,
    addresses: Addresses,
    network_links_priority_map: NetworkLinksPriorityMap,
    wireguard_keepalive_interval_map: WireguardKeepaliveIntervalMap,
    providers: Vec<Provider>,
}

#[salsa::query_group(MachineDataStorage)]
trait MachineData: salsa::Database {
    #[salsa::input]
    fn connection_wrapper(&self) -> Arc<PgConnectionWrapper>;
    fn data(&self) -> Arc<AllData>;
}

fn data(db: &impl MachineData) -> Arc<AllData> {
    let ref connection = db.connection_wrapper().connection;

    connection.transaction::<_, Error, _>(|| {
        let machines = machines::table
            .load::<Machine>(connection)?;
        let addresses = MachineAddress::belonging_to(&machines)
            .load::<MachineAddress>(connection)?
            .grouped_by(&machines);
        // Some users need it sorted
        let mut machines_and_addresses = machines.into_iter().zip(addresses).collect::<Vec<_>>();
        sort_machines_and_addresses(&mut machines_and_addresses);

        let mut addresses = machine_addresses::table
            .load::<MachineAddress>(connection)?;
        // Some users need it sorted
        sort_addresses(&mut addresses);

        let network_links_priority_map = network_links::table
            .load::<NetworkLink>(connection)?
            .into_iter()
            .map(|row| ((row.name, row.other_network), row.priority))
            .collect::<HashMap<_, _>>();

        let wireguard_keepalive_interval_map = wireguard_keepalives::table
            .load::<WireguardKeepalive>(connection)?
            .into_iter()
            .map(|row| ((row.source_machine, row.target_machine), row.interval_sec))
            .collect::<HashMap<_, _>>();

        let providers = providers::table
            .load::<Provider>(connection)?;

        Ok(Arc::new(AllData {
            machines_and_addresses,
            addresses,
            network_links_priority_map,
            wireguard_keepalive_interval_map,
            providers,
        }))
    }).unwrap()
}

#[salsa::database(MachineDataStorage)]
#[derive(Default)]
pub(crate) struct DatabaseStruct {
    runtime: salsa::Runtime<DatabaseStruct>,
}

impl salsa::Database for DatabaseStruct {
    fn salsa_runtime(&self) -> &salsa::Runtime<Self> {
        &self.runtime
    }

    fn salsa_runtime_mut(&mut self) -> &mut salsa::Runtime<Self> {
        &mut self.runtime
    }
}
