#![feature(proc_macro_hygiene)]

pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate itertools;

use std::collections::{HashMap, HashSet};
use std::{env, path::PathBuf};
use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv;
use snafu::{ResultExt, Snafu};
use structopt::StructOpt;
use indoc::indoc;
use natural_sort::HumanStr;
use ipnetwork::IpNetwork;
use std::net::Ipv4Addr;

use schema::{machines, network_links};
use models::{Machine, MachineAddress, NetworkLink};

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Unable to read configuration from {}: {}", path.display(), source))]
    ReadConfiguration { source: dotenv::DotenvError, path: PathBuf },

    #[snafu(display("Could not find source machine {:?} in database", source_machine))]
    MissingSourceMachine { source_machine: String },

    Diesel { source: diesel::result::Error },

    DieselConnection { source: diesel::ConnectionError },

    Var { source: env::VarError },
}

impl From<diesel::result::Error> for Error {
    fn from(source: diesel::result::Error) -> Self {
        Error::Diesel { source }
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

type DieselResult<T> = Result<T, diesel::result::Error>;

fn import_env() -> Result<()> {
    let path = dirs::config_dir().unwrap().join("infrabase").join("env");
    dotenv::from_path(&path).context(ReadConfiguration { path })
}

fn establish_connection() -> Result<PgConnection> {
    let database_url = env::var("DATABASE_URL").context(Var)?;
    Ok(PgConnection::establish(&database_url).context(DieselConnection)?)
}

/// A map of (network, other_network) -> priority
type NetworkLinksMap = HashMap<(String, String), i32>;

fn get_network_links_map(connection: &PgConnection) -> DieselResult<NetworkLinksMap> {
    let map = network_links::table
        .load::<NetworkLink>(connection)?
        .into_iter()
        .map(|row| ((row.name, row.other_network), row.priority))
        .collect::<HashMap<_, _>>();
    Ok(map)
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

fn get_existing_wireguard_ips(connection: &PgConnection) -> Result<impl Iterator<Item=IpNetwork>> {
    Ok(machines::table
        .load::<Machine>(connection)?
        .into_iter()
        .filter_map(|row| row.wireguard_ip))
}

fn increment_ip(ip: &Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    for i in (0..4).rev() {
        if octets[i] < 255 {
            octets[i] += 1;
            break;
        } else {
            octets[i] = 0;
        }
    }
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

//fn get_unused_wireguard_ip(connection: &PgConnection, start_ip: IpNetwork) -> Result<IpNetwork> {
//    let existing = get_existing_wireguard_ips().collect::<HashSet<IpNetwork>>();
//
//}

fn add_machine(hostname: &str, wireguard_ip: &Option<String>, wireguard_pubkey: &Option<String>) -> Result<()> {
    let connection = establish_connection()?;

    println!("{}", hostname);

    println!("{:#?}", get_existing_wireguard_ips(&connection)?.collect::<Vec<_>>());

    // let wireguard_ip = match wireguard_ip {
    //     Some(ip) => ip,
    //     None => {
    //         // Do this inside transaction
    //         println!("{:?}", get_existing_wireguard_ips(&connection));
    //     }
    // };

    Ok(())
}

fn print_ssh_config(for_machine: &str) -> Result<()> {
    let connection = establish_connection()?;
    let (data, network_links_map) = connection.transaction::<_, Error, _>(|| {
        let data = get_machines_and_addresses(&connection)?;
        let network_links_map = get_network_links_map(&connection)?;
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

#[derive(StructOpt, Debug)]
#[structopt(name = "infrabase")]
/// the machine inventory system
enum Opt {
    #[structopt(name = "ls")]
    /// List machines
    List,
    #[structopt(name = "add")]
    /// Add machine
    Add {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,

        /// WireGuard IP
        wireguard_ip: Option<String>,

        /// WireGuard public key
        wireguard_pubkey: Option<String>,
    },
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
        Opt::List => {
            list_machines()?;
        },
        Opt::Add { hostname, wireguard_ip, wireguard_pubkey } => {
            add_machine(&hostname, &wireguard_ip, &wireguard_pubkey)?;
        },
        Opt::SshConfig { r#for } => {
            print_ssh_config(&r#for)?;
        },
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(())   => {},
        Err(err) => eprintln!("An error occurred:\n{}", err),
    }
}

#[cfg(test)]
mod tests {
    use super::increment_ip;
    use std::net::Ipv4Addr;

    #[test]
    fn test_increment_ip() {
        assert_eq!(increment_ip(&Ipv4Addr::new(0, 0,   0,   0)),   Ipv4Addr::new(0, 0, 0,   1));
        assert_eq!(increment_ip(&Ipv4Addr::new(0, 0,   0,   1)),   Ipv4Addr::new(0, 0, 0,   2));
        assert_eq!(increment_ip(&Ipv4Addr::new(0, 0,   1,   255)), Ipv4Addr::new(0, 0, 2,   0));
        assert_eq!(increment_ip(&Ipv4Addr::new(0, 0,   255, 0)),   Ipv4Addr::new(0, 0, 255, 1));
        assert_eq!(increment_ip(&Ipv4Addr::new(0, 2,   255, 255)), Ipv4Addr::new(0, 3, 0,   0));
        assert_eq!(increment_ip(&Ipv4Addr::new(3, 255, 255, 255)), Ipv4Addr::new(4, 0, 0,   0));
//        assert_raise(
//            FunctionClauseError,
//        fn -> increment_ip({255, 255, 255, 255}) end
//        )
    }
}
