#![feature(proc_macro_hygiene)]

pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate itertools;

use std::collections::HashMap;
use std::{env, path::PathBuf};
use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv;
use snafu::{ResultExt, Snafu};
use structopt::StructOpt;
use indoc::indoc;
use natural_sort::HumanStr;

use schema::{machines, network_links};
use models::{Machine, MachineAddress, NetworkLink};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Unable to read configuration from {}: {}", path.display(), source))]
    ReadConfiguration { source: dotenv::DotenvError, path: PathBuf },

    #[snafu(display("Could not find source machine {:?} in database", source_machine))]
    MissingSourceMachine { source_machine: String },

    #[snafu(source(from(diesel::result::Error, Box::new)))]
    DieselError { source: diesel::result::Error },

    #[snafu(source(from(diesel::ConnectionError, Box::new)))]
    DieselConnectionError { source: diesel::ConnectionError },

    #[snafu(source(from(env::VarError, Box::new)))]
    VarError { source: env::VarError },
}

impl From<diesel::result::Error> for Error {
    fn from(source: diesel::result::Error) -> Self {
        Error::DieselError { source }
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

type DieselResult<T> = Result<T, diesel::result::Error>;

fn import_env() -> Result<()> {
    let path = dirs::config_dir().unwrap().join("infrabase").join("env");
    dotenv::from_path(&path).context(ReadConfiguration { path })
}

fn establish_connection() -> Result<PgConnection> {
    let database_url = env::var("DATABASE_URL").context(VarError)?;
    Ok(PgConnection::establish(&database_url).context(DieselConnectionError)?)
}

/// A map of (network, other_network) -> priority
type NetworkLinksMap = HashMap<(String, String), i32>;

fn get_network_links_map(connection: &PgConnection) -> NetworkLinksMap {
    network_links::table
        .load::<NetworkLink>(connection)
        .expect("Error loading network_links")
        .into_iter()
        .map(|row| ((row.name, row.other_network), row.priority))
        .collect::<HashMap<_, _>>()
}

fn get_machines_and_addresses(connection: &PgConnection) -> DieselResult<Vec<(Machine, Vec<MachineAddress>)>> {
    connection.transaction::<_, _, _>(|| {
        let machines = machines::table
            .load::<Machine>(connection)?;

        let addresses = MachineAddress::belonging_to(&machines)
            .load::<MachineAddress>(connection)?
            .grouped_by(&machines);

        Ok(machines.into_iter().zip(addresses).collect::<Vec<_>>())
    })
}

fn print_ssh_config(for_machine: &str) -> Result<()> {
    let connection = establish_connection()?;
    let (data, network_links_map) = connection.transaction::<_, Error, _>(|| {
        let data = get_machines_and_addresses(&connection)?;
        let network_links_map = get_network_links_map(&connection);
        Ok((data, network_links_map))
    })?;
    let source_machine = data.iter().find(|(machine, _)| machine.hostname == for_machine);
    let source_networks = match source_machine {
        None => return Err(Error::MissingSourceMachine { source_machine: for_machine.into() }),
        Some((_, addresses)) => {
            addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>()
        }
    };

    println!("# infrabase-generated SSH config for {}\n", for_machine);

    for (machine, addresses) in &data {
        let dest_networks = addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>();
        let mut network_to_network = iproduct!(&source_networks, &dest_networks)
            .filter(|(s, d)| network_links_map.contains_key(&(s.to_string(), d.to_string())))
            .collect::<Vec<_>>();
        network_to_network.sort_unstable_by_key(|(s, d)| network_links_map.get(&(s.to_string(), d.to_string())).unwrap());
        let (address, ssh_port) = match network_to_network.get(0) {
            None => {
                // We prefer to SSH over the non-WireGuard IP in case WireGuard is down,
                // but if there is no reachable address, use the WireGuard IP instead.
                (machine.wireguard_ip.map(|o| o.ip()), machine.ssh_port)
            },
            Some((_, dest_network)) => {
                let desired_address = addresses.iter().find(|a| a.network == **dest_network).unwrap();
                (Some(desired_address.address.ip()), desired_address.ssh_port)
            }
        };

        if let (Some(address), Some(port)) = (address, ssh_port) {
            println!(indoc!("
                # owner: {}
                Host {}
                  HostName {}
                  Port {}
            "), machine.owner, machine.hostname, address, port);
        }
    }
    Ok(())
}

fn list_machines() -> Result<()> {
    let connection = establish_connection()?;

    let mut data = get_machines_and_addresses(&connection)?;

    // natural_sort refuses to compare string segments with integer segments,
    // so if returns None, fall back to String cmp.
    data.sort_unstable_by(|(m1, _), (m2, _)| {
        HumanStr::new(&m1.hostname)
            .partial_cmp(&HumanStr::new(&m2.hostname))
            .unwrap_or_else(|| m1.hostname.cmp(&m2.hostname))
    });

    for (machine, _addresses) in &data {
        println!("{}", machine.hostname);
    }

    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "infrabase")]
/// the machine inventory system
enum Opt {
    #[structopt(name = "ssh_config")]
    /// Prints an ~/.ssh/config that lists all machines
    SshConfig {
        /// Machine to generate SSH config for
        #[structopt(long = "for", name = "MACHINE")]
        r#for: String,
    },
    #[structopt(name = "ls")]
    /// List machines
    List,
}

fn run() -> Result<()> {
    import_env()?;
    env_logger::init();

    let matches = Opt::from_args();
    match matches {
        Opt::SshConfig { r#for } => {
            print_ssh_config(&r#for)?;
        },
        Opt::List => {
            list_machines()?;
        }
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(())   => {},
        Err(err) => eprintln!("An error occurred:\n{}", err),
    }
}
