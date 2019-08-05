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
use ifmt::iprintln;
use indoc::indoc;

use schema::{machines, network_links};
use models::{Machine, MachineAddress, NetworkLink};

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Unable to read configuration from {}: {}", path.display(), source))]
    ReadConfiguration { source: dotenv::DotenvError, path: PathBuf },

    #[snafu(display("Could not find source machine {:?} in database", source_machine))]
    MissingSourceMachine { source_machine: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn import_env() -> Result<()> {
    let path = dirs::config_dir().unwrap().join("infrabase").join("env");
    dotenv::from_path(&path).context(ReadConfiguration { path })
}

fn establish_connection() -> PgConnection {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

/// A map of (network, other_network) -> priority
type NetworkLinksMap = HashMap<(String, String), i32>;

fn get_networks_links_map(connection: &PgConnection) -> NetworkLinksMap {
    network_links::table
        .load::<NetworkLink>(connection)
        .expect("Error loading network_links")
        .into_iter()
        .map(|row| ((row.name, row.other_network), row.priority))
        .collect::<HashMap<_, _>>()
}

fn print_ssh_config(for_machine: &str) -> Result<()> {
    let connection = establish_connection();

    let machines = machines::table
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    let addresses = MachineAddress::belonging_to(&machines)
        .load::<MachineAddress>(&connection)
        .expect("Error loading addresses")
        .grouped_by(&machines);

    let data = machines.into_iter().zip(addresses).collect::<Vec<_>>();
    let source_machine = data.iter().find(|(machine, _)| machine.hostname == for_machine);
    let source_networks = match source_machine {
        None => return Err(Error::MissingSourceMachine { source_machine: for_machine.into() }),
        Some((_, addresses)) => {
            addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>()
        }
    };

    println!("# infrabase-generated SSH config for {}\n", for_machine);

    let networks_links_map = get_networks_links_map(&connection);

    for (machine, addresses) in &data {
        let dest_networks = addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>();
        let mut network_to_network = iproduct!(&source_networks, &dest_networks)
            .filter(|(s, d)| networks_links_map.contains_key(&(s.to_string(), d.to_string())))
            .collect::<Vec<_>>();
        network_to_network.sort_by_key(|(s, d)| networks_links_map.get(&(s.to_string(), d.to_string())).unwrap());
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

        match (address, ssh_port) {
            (Some(address), Some(port)) => {
                iprintln!("\
# owner: {machine.owner}
Host {machine.hostname}
  HostName {address}
  Port {port}
                ");
            },
            _ => {}
        }
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
}

fn run() -> Result<()> {
    import_env()?;
    env_logger::init();

    let matches = Opt::from_args();
    match matches {
        Opt::SshConfig { r#for } => {
            print_ssh_config(&r#for)?;
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
