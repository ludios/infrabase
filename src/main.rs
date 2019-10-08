#![feature(proc_macro_hygiene)]
#![feature(result_map_or_else)]

pub mod schema;
pub mod models;
mod wireguard;
mod nix;
#[macro_use] mod macros;

#[macro_use] extern crate diesel;
#[macro_use] extern crate itertools;
#[macro_use] extern crate runtime_fmt;

use std::io;
use std::iter;
use std::collections::{HashMap, HashSet};
use std::{env, path::PathBuf};
use std::net::{IpAddr, Ipv4Addr};
use std::io::Write;
use std::fs::File;
use std::str;
use std::string::ToString;
use std::convert::TryFrom;
use tabwriter::{TabWriter, IntoInnerError};
use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv;
use snafu::{ensure, ResultExt, Snafu, Backtrace, ErrorCompat};
use structopt::StructOpt;
use indoc::indoc;
use natural_sort::HumanStr;
use ipnetwork::IpNetwork;
use itertools::Itertools;

use nix::ToNix;
use schema::{machines, machine_addresses, network_links, providers, wireguard_keepalives};
use models::{Machine, NewMachine, MachineAddress, NetworkLink, Provider, WireguardKeepalive};

#[derive(Debug, Snafu)]
pub(crate) enum Error {
    #[snafu(display("Unable to read configuration from {}: {}", path.display(), source))]
    ReadConfiguration { source: dotenv::DotenvError, path: PathBuf },
    #[snafu(display("Could not find machine {:?} in database", hostname))]
    NoSuchMachine { hostname: String },
    #[snafu(display("Could not find address ({:?}, {:?}, {:?}) in database", hostname, network, address))]
    NoSuchAddress { hostname: String, network: String, address: IpNetwork },
    Diesel { source: diesel::result::Error },
    DieselConnection { source: diesel::ConnectionError },
    #[snafu(display("Could not get variable {} from environment", var))]
    Var { source: env::VarError, var: String },
    Io { source: std::io::Error, backtrace: Backtrace },
    IntoInner { source: IntoInnerError<TabWriter<Vec<u8>>> },
    #[snafu(display("Could not parse variable {} as integer", var))]
    ParseInt { source: std::num::ParseIntError, var: String },
    #[snafu(display("Could not parse variable {} as IP address", var))]
    AddrParse { source: std::net::AddrParseError, var: String },
    #[snafu(display("Could not find an unused WireGuard IP address; check WIREGUARD_IP_START and WIREGUARD_IP_END"))]
    NoWireguardAddressAvailable,
    #[snafu(display("Machine {} does not have WireGuard", hostname))]
    MachineHasNoWireguard { hostname: String },
    NonZeroExit,
    NoStdin,
    FormatString,
    NoParentDirectory,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io {
            source: err,
            backtrace: Backtrace::new(),
        }
    }
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
    let database_url = env_var("DATABASE_URL")?;
    Ok(PgConnection::establish(&database_url).context(DieselConnection)?)
}

/// A map of (network, other_network) -> priority
type NetworkLinksPriorityMap = HashMap<(String, String), i32>;

/// A map of (source_machine, target_machine) -> interval
type WireguardKeepaliveIntervalMap = HashMap<(String, String), i32>;

fn get_network_links_priority_map(connection: &PgConnection) -> DieselResult<NetworkLinksPriorityMap> {
    let map = network_links::table
        .load::<NetworkLink>(connection)?
        .into_iter()
        .map(|row| ((row.name, row.other_network), row.priority))
        .collect::<HashMap<_, _>>();
    Ok(map)
}

fn get_wireguard_keepalive_map(connection: &PgConnection) -> DieselResult<WireguardKeepaliveIntervalMap> {
    let map = wireguard_keepalives::table
        .load::<WireguardKeepalive>(connection)?
        .into_iter()
        .map(|row| ((row.source_machine, row.target_machine), row.interval_sec))
        .collect::<HashMap<_, _>>();
    Ok(map)
}

type MachinesAndAddresses = Vec<(Machine, Vec<MachineAddress>)>;

fn get_machines_and_addresses(connection: &PgConnection) -> DieselResult<MachinesAndAddresses> {
    connection.transaction::<_, _, _>(|| {
        let machines = machines::table
            .load::<Machine>(connection)?;

        let addresses = MachineAddress::belonging_to(&machines)
            .load::<MachineAddress>(connection)?
            .grouped_by(&machines);

        Ok(machines.into_iter().zip(addresses).collect::<Vec<_>>())
    })
}

fn format_port(port: Option<i32>) -> String {
    match port {
        Some(port) => port.to_string(),
        None => "-".to_string(),
    }
}

fn format_wireguard_ip(wireguard_ip: &Option<IpNetwork>) -> String {
    match wireguard_ip {
        Some(ipnetwork) => ipnetwork.ip().to_string(),
        None => "-".to_string(),
    }
}

fn format_provider(provider: Option<i32>) -> String {
    match provider {
        Some(p) => p.to_string(),
        None => "-".to_string(),
    }
}

fn format_provider_reference(reference: &Option<String>) -> String {
    match reference {
        Some(p) => p.to_string(),
        None => "-".to_string(),
    }
}

fn print_tabwriter(tw: TabWriter<Vec<u8>>) -> Result<()> {
    let bytes = tw.into_inner().context(IntoInner)?;
    std::io::stdout().write_all(&bytes).context(Io)
}

/// Write a table header to a TabWriter
fn write_column_names(tw: &mut TabWriter<Vec<u8>>, headers: Vec<&str>) -> Result<()> {
    tw.write_all(headers.join("\t").as_bytes()).context(Io)?;
    tw.write_all("\n".as_bytes()).context(Io)?;
    tw.write_all(headers.iter().map(|h| str::repeat("-", h.len())).join("\t").as_bytes()).context(Io)?;
    tw.write_all("\n".as_bytes()).context(Io)?;
    Ok(())
}

fn list_providers(connection: &PgConnection) -> Result<()> {
    let providers = providers::table
        .load::<Provider>(connection)?;

    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["ID", "NAME", "EMAIL"])?;
    for provider in &providers {
        writeln!(tw, "{}\t{}\t{}",
                 provider.id,
                 provider.name,
                 provider.email
        ).context(Io)?;
    }
    print_tabwriter(tw)
}

fn list_wireguard_keepalives(connection: &PgConnection) -> Result<()> {
    let keepalives = wireguard_keepalives::table
        .load::<WireguardKeepalive>(connection)?;

    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["SOURCE", "TARGET", "INTERVAL"])?;
    for keepalive in &keepalives {
        writeln!(tw, "{}\t{}\t{}",
                 keepalive.source_machine,
                 keepalive.target_machine,
                 keepalive.interval_sec
        ).context(Io)?;
    }
    print_tabwriter(tw)
}

fn add_address(
    connection: &PgConnection,
    hostname: &str,
    network: &str,
    address: Ipv4Addr,
    ssh_port: Option<u16>,
    wireguard_port: Option<u16>
) -> Result<()> {
    let ssh_port = unwrap_or_else!(ssh_port, env_var("DEFAULT_SSH_PORT")?.parse::<u16>().context(ParseInt { var: "DEFAULT_SSH_PORT" })?);
    let wireguard_port = unwrap_or_else!(wireguard_port, env_var("DEFAULT_WIREGUARD_PORT")?.parse::<u16>().context(ParseInt { var: "DEFAULT_WIREGUARD_PORT" })?);
    let ipnetwork = IpNetwork::new(IpAddr::V4(address), 32).unwrap();
    let new_address = MachineAddress {
        hostname: hostname.into(),
        network: network.into(),
        address: ipnetwork,
        ssh_port: Some(i32::from(ssh_port)),
        wireguard_port: Some(i32::from(wireguard_port)),
    };

    diesel::insert_into(machine_addresses::table)
        .values(&new_address)
        .execute(connection)?;

    Ok(())
}

fn remove_address(connection: &PgConnection, hostname: &str, network: &str, address: Ipv4Addr) -> Result<()> {
    let ipnetwork = IpNetwork::new(IpAddr::V4(address), 32).unwrap();
    let num_deleted = diesel::delete(
        machine_addresses::table
            .filter(machine_addresses::hostname.eq(hostname))
            .filter(machine_addresses::network.eq(network))
            .filter(machine_addresses::address.eq(ipnetwork))
    ).execute(connection)?;
    ensure!(num_deleted == 1, NoSuchAddress { hostname: hostname, network: network, address: ipnetwork });
    Ok(())
}

fn list_addresses(connection: &PgConnection) -> Result<()> {
    let mut addresses = machine_addresses::table
        .load::<MachineAddress>(connection)?;

    // natural_sort refuses to compare string segments with integer segments,
    // so if returns None, fall back to String cmp.
    addresses.sort_unstable_by(|a1, a2| {
        HumanStr::new(&a1.hostname)
            .partial_cmp(&HumanStr::new(&a2.hostname))
            .unwrap_or_else(|| a1.hostname.cmp(&a2.hostname))
    });

    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["HOSTNAME", "NETWORK", "ADDRESS", "SSH", "WG"])?;
    for address in &addresses {
        writeln!(tw, "{}\t{}\t{}\t{}\t{}",
                 address.hostname,
                 address.network,
                 address.address,
                 format_port(address.ssh_port),
                 format_port(address.wireguard_port),
        ).context(Io)?;
    }
    print_tabwriter(tw)
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

fn list_machines(connection: &PgConnection) -> Result<()> {
    let mut data = get_machines_and_addresses(&connection)?;
    sort_machines_and_addresses(&mut data);
    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["HOSTNAME", "WIREGUARD", "OWNER", "PROV", "REFERENCE", "ADDRESSES"])?;
    for (machine, addresses) in &data {
        writeln!(tw, "{}\t{}\t{}\t{}\t{}\t{}",
                 machine.hostname,
                 format_wireguard_ip(&machine.wireguard_ip),
                 machine.owner,
                 format_provider(machine.provider_id),
                 format_provider_reference(&machine.provider_reference),
                 addresses.iter().map(|a| {
                     format!("{}={}", a.network, a.address.ip())
                 }).join(" ")
        ).context(Io)?;
    }
    print_tabwriter(tw)
}

fn format_nix_address(address: &MachineAddress) -> String {
    format!("{} = {{ ip = {}; ssh_port = {}; wireguard_port = {}; }}; ",
            address.network,
            address.address.ip().to_nix(),
            address.ssh_port.to_nix(),
            address.wireguard_port.to_nix()
    )
}

fn nix_data(connection: &PgConnection) -> Result<()> {
    let mut data = get_machines_and_addresses(&connection)?;
    sort_machines_and_addresses(&mut data);

    println!("{{");
    let mut tw = TabWriter::new(vec![]).padding(1);
    for (machine, addresses) in &data {
        writeln!(tw, "  {}\t= {{ owner = {};\twireguard_ip = {};\twireguard_port = {};\tssh_port = {};\tprovider_id = {};\tprovider_reference = {};\taddresses = {{ {}}}; }};",
                 machine.hostname,
                 machine.owner.to_nix(),
                 format_wireguard_ip(&machine.wireguard_ip).to_nix(),
                 machine.wireguard_port.to_nix(),
                 machine.ssh_port.to_nix(),
                 &machine.provider_id.to_nix(),
                 &machine.provider_reference.to_nix(),
                 addresses.iter().map(format_nix_address).join("")
        ).context(Io)?;
    }
    print_tabwriter(tw)?;
    println!("}}");
    Ok(())
}

fn print_wireguard_privkey(connection: &PgConnection, hostname: &str) -> Result<()> {
    let machine = machines::table
        .find(hostname)
        .first::<Machine>(connection)?;
    ensure!(machine.wireguard_privkey.is_some(), MachineHasNoWireguard { hostname });
    println!("{}", machine.wireguard_privkey.unwrap());
    Ok(())
}

fn write_wireguard_peers(connection: &PgConnection) -> Result<()> {
    let path_template = env_var("WIREGUARD_PEERS_PATH_TEMPLATE")?;

    let data = get_machines_and_addresses(&connection)?;
    for (machine, _addresses) in &data {
        let hostname = &machine.hostname;
        let wireguard_ip = &machine.wireguard_ip;
        let path = rt_format!(path_template, hostname = hostname, wireguard_ip = wireguard_ip).map_err(|_| Error::FormatString)?;
        let mut file = File::create(path)?;
        file.write_all(b"")?;
    }
    Ok(())
}

fn get_existing_wireguard_ips(connection: &PgConnection) -> Result<impl Iterator<Item=IpNetwork>> {
    Ok(machines::table
        .load::<Machine>(connection)?
        .into_iter()
        .filter_map(|row| row.wireguard_ip))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn increment_ip(ip: &Ipv4Addr) -> Option<Ipv4Addr> {
    let mut octets = ip.octets();
    if octets == [255, 255, 255, 255] {
        return None;
    }
    for i in (0..4).rev() {
        if octets[i] < 255 {
            octets[i] += 1;
            break;
        } else {
            octets[i] = 0;
        }
    }
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn get_unused_wireguard_ip(connection: &PgConnection, start_ip: Ipv4Addr, end_ip: Ipv4Addr) -> Result<IpNetwork> {
    let existing = get_existing_wireguard_ips(&connection)?.collect::<HashSet<IpNetwork>>();
    let ip_iter = iter::successors(Some(start_ip), increment_ip);
    for proposed_ip in ip_iter {
        let ipnetwork = IpNetwork::new(IpAddr::V4(proposed_ip), 32).unwrap();
        if !existing.contains(&ipnetwork) {
            return Ok(ipnetwork);
        }
        if proposed_ip == end_ip {
            break;
        }
    }
    Err(Error::NoWireguardAddressAvailable)
}

fn env_var(var: &str) -> Result<String> {
    env::var(var).context(Var { var })
}

#[allow(clippy::too_many_arguments)]
fn add_machine(
    connection: &PgConnection,
    hostname: &str,
    owner: Option<String>,
    ssh_port: Option<u16>,
    ssh_user: Option<String>,
    wireguard_ip: Option<Ipv4Addr>,
    wireguard_port: Option<u16>,
    provider: Option<u32>,
    provider_reference: Option<String>,
) -> Result<()> {
    // Required environmental variables
    let start_ip       = env_var("WIREGUARD_IP_START")?.parse::<Ipv4Addr>().context(AddrParse { var: "WIREGUARD_IP_START" })?;
    let end_ip         = env_var("WIREGUARD_IP_END")?.parse::<Ipv4Addr>().context(AddrParse { var: "WIREGUARD_IP_END" })?;
    // Optional environmntal variables
    let ssh_port       = unwrap_or_else!(ssh_port, env_var("DEFAULT_SSH_PORT")?.parse::<u16>().context(ParseInt { var: "DEFAULT_SSH_PORT" })?);
    let ssh_user       = unwrap_or_else!(ssh_user, env_var("DEFAULT_SSH_USER")?);
    let wireguard_port = unwrap_or_else!(wireguard_port, env_var("DEFAULT_WIREGUARD_PORT")?.parse::<u16>().context(ParseInt { var: "DEFAULT_WIREGUARD_PORT" })?);
    let owner          = unwrap_or_else!(owner, env_var("DEFAULT_OWNER")?);
    let provider_id    = ok_or_else!(provider,
        match env_var("DEFAULT_PROVIDER") {
            Ok(s) => Some(s.parse::<u32>().context(ParseInt { var: "DEFAULT_PROVIDER" })?),
            Err(_) => None,
        }
    );

    let wireguard_ip = match wireguard_ip {
        Some(ip) => IpNetwork::new(IpAddr::V4(ip), 32).unwrap(),
        None => get_unused_wireguard_ip(&connection, start_ip, end_ip)?,
    };
    let keypair = wireguard::generate_keypair()?;

    let machine = NewMachine {
        hostname: hostname.into(),
        wireguard_ip: Some(wireguard_ip),
        wireguard_port: Some(i32::from(wireguard_port)),
        wireguard_privkey: Some(str::from_utf8(&keypair.privkey).unwrap().to_string()),
        wireguard_pubkey: Some(str::from_utf8(&keypair.pubkey).unwrap().to_string()),
        ssh_port: Some(i32::from(ssh_port)),
        ssh_user: Some(ssh_user),
        owner,
        provider_id: provider_id.map(|n| i32::try_from(n).unwrap()),
        provider_reference,
    };

    diesel::insert_into(machines::table)
        .values(&machine)
        .execute(connection)?;

    Ok(())
}

fn remove_machine(connection: &PgConnection, hostname: &str) -> Result<()> {
    let num_deleted = diesel::delete(machines::table.filter(machines::hostname.eq(hostname)))
        .execute(connection)?;
    ensure!(num_deleted == 1, NoSuchMachine { hostname });
    Ok(())
}

#[allow(clippy::ptr_arg)]
fn get_source_networks(data: &MachinesAndAddresses, for_machine: &str) -> Result<Vec<String>> {
    let source_machine = data.iter().find(|(machine, _)| machine.hostname == for_machine);
    ensure!(source_machine.is_some(), NoSuchMachine { hostname: for_machine });
    let addresses = &source_machine.unwrap().1;
    Ok(addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>())
}

/// Return a Vec of (source_network, dest_network) pairs appropriate for
/// establishing a connection to `addresses`, highest priority first
fn get_network_to_network(
    network_links_priority_map: &NetworkLinksPriorityMap,
    source_networks: &[String],
    addresses: &[MachineAddress],
) -> Vec<(String, String)> {
    // Convert because we need Strings in our return
    let source_networks = source_networks.iter().map(String::from).collect::<Vec<_>>();

    // Networks the destination machine is on
    let dest_networks = addresses.iter().map(|a| a.network.clone()).collect::<Vec<_>>();

    // (source, dest) network pairs
    let mut network_to_network = iproduct!(source_networks, dest_networks)
        .filter(|(s, d)| network_links_priority_map.contains_key(&(s.to_string(), d.to_string())))
        .collect::<Vec<(String, String)>>();
    network_to_network.sort_unstable_by_key(|(s, d)| network_links_priority_map.get(&(s.to_string(), d.to_string())).unwrap());
    network_to_network
}

fn print_ssh_config(connection: &PgConnection, for_machine: &str) -> Result<()> {
    let (mut data, network_links_priority_map) = connection.transaction::<_, Error, _>(|| {
        Ok((
            get_machines_and_addresses(&connection)?,
            get_network_links_priority_map(&connection)?
        ))
    })?;
    sort_machines_and_addresses(&mut data);
    let source_networks = get_source_networks(&data, for_machine)?;

    println!("# infrabase-generated SSH config for {}\n", for_machine);

    for (machine, addresses) in &data {
        let network_to_network = get_network_to_network(&network_links_priority_map, &source_networks, addresses);
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

fn print_wg_quick(connection: &PgConnection, for_machine: &str) -> Result<()> {
    let (data, network_links_priority_map, keepalives_map) = connection.transaction::<_, Error, _>(|| {
        Ok((
            get_machines_and_addresses(&connection)?,
            get_network_links_priority_map(&connection)?,
            get_wireguard_keepalive_map(connection)?,
        ))
    })?;
    let source_networks = get_source_networks(&data, for_machine)?;

    let (my_machine, _) = data.iter().find(|(machine, _)| machine.hostname == for_machine).unwrap();
    ensure!(my_machine.wireguard_ip.is_some(), MachineHasNoWireguard { hostname: for_machine });

    println!(indoc!("
        # infrabase-generated wg-quick config for {}

        [Interface]
        Address = {}/32
        PrivateKey = {}
        ListenPort = {}
    "), for_machine, my_machine.wireguard_ip.unwrap().ip(), my_machine.wireguard_privkey.as_ref().unwrap(), my_machine.wireguard_port.unwrap());

    for (machine, addresses) in &data {
        if machine.hostname == for_machine {
            // We don't need a [Peer] for ourselves
            continue;
        }
        let network_to_network = get_network_to_network(&network_links_priority_map, &source_networks, addresses);
        let endpoint = match network_to_network.get(0) {
            Some((_, dest_network)) => {
                let desired_address = addresses.iter().find(|a| a.network == **dest_network);
                match desired_address {
                    Some(MachineAddress { address, wireguard_port: Some(port), .. }) => {
                        Some((address.ip(), port))
                    },
                    _ => None,
                }
            },
            None => None,
        };

        // If we have a wireguard peer
        if let (Some(wireguard_ip), Some(wireguard_pubkey)) = (machine.wireguard_ip, &machine.wireguard_pubkey) {
            // If we have an endpoint for the wireguard peer
            let maybe_endpoint = match endpoint {
                Some((address, port)) => format!("Endpoint = {}:{}\n", address, port),
                None => "".to_string(),
            };
            let maybe_keepalive = match keepalives_map.get(&(my_machine.hostname.to_string(), machine.hostname.to_string())) {
                Some(interval) => format!("PersistentKeepalive = {}\n", interval),
                None => "".to_string()
            };
            println!(indoc!("
                # {}
                [Peer]
                PublicKey = {}
                AllowedIPs = {}
                {}\
                {}\
            "), machine.hostname, wireguard_pubkey, wireguard_ip, maybe_endpoint, maybe_keepalive);
        }
    }
    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "infrabase")]
#[structopt(help_message = "Print help information")]
#[structopt(version_message = "Print version information")]
/// the machine inventory system
enum InfrabaseCommand {
    /// Subcommands to work with WireGuard persistent keepalives
    #[structopt(name = "wg-keepalive")]
    WireguardKeepalive(WireguardKeepaliveCommand),

    #[structopt(name = "wg-privkey")]
    /// Print a machine's private WireGuard key
    WireguardPrivkey {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,
    },

    #[structopt(name = "write-wg-peers")]
    /// Write out all WireGuard peers files used for NixOS configuration
    WriteWireguardPeers,

    /// Subcommands to work with providers
    #[structopt(name = "provider")]
    Provider(ProviderCommand),

    /// Subcommands to work with addresses
    #[structopt(name = "address")]
    Address(AddressCommand),

    #[structopt(name = "ls")]
    /// List machines
    List,

    #[structopt(name = "nix-data")]
    /// Output machine and address data in Nix format for use in configuration
    NixData,

    #[structopt(name = "add")]
    /// Add machine
    Add {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,

        /// Machine owner
        ///
        /// If one is not provided, DEFAULT_OWNER will be used from the environment.
        #[structopt(long)]
        owner: Option<String>,

        /// SSH port
        ///
        /// If one is not provided, DEFAULT_SSH_PORT will be used from the environment.
        #[structopt(long)]
        ssh_port: Option<u16>,

        /// SSH user
        ///
        /// If one is not provided, DEFAULT_SSH_USER will be used from the environment.
        #[structopt(long)]
        ssh_user: Option<String>,

        /// WireGuard IP
        ///
        /// If one is not provided, an unused IP address will be selected.
        #[structopt(long)]
        wireguard_ip: Option<Ipv4Addr>,

        /// WireGuard port
        ///
        /// If one is not provided, DEFAULT_WIREGUARD_PORT will be used from the environment.
        #[structopt(long)]
        wireguard_port: Option<u16>,

        /// Provider
        ///
        /// If one is not provided, DEFAULT_OWNER will be used from the environment
        /// if set, otherwise it will be left unset.
        #[structopt(long)]
        provider: Option<u32>,

        /// Provider reference
        ///
        /// An optional arbitrary string used to correlate this machine with some reference
        /// at the provider, like a contract ID or a server number.
        #[structopt(long)]
        provider_reference: Option<String>,
    },

    #[structopt(name = "rm")]
    /// Remove machine
    Remove {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,
    },

    #[structopt(name = "ssh_config")]
    /// Prints an ~/.ssh/config that lists all machines
    SshConfig {
        /// Machine to generate SSH config for
        #[structopt(long = "for", name = "MACHINE")]
        r#for: String,
    },

    #[structopt(name = "wg_quick")]
    /// Output a wg-quick config for a machine
    WgQuick {
        /// Machine to generate wg-quick config for
        #[structopt(long = "for", name = "MACHINE")]
        r#for: String,
    },
}

#[derive(StructOpt, Debug)]
enum WireguardKeepaliveCommand {
    #[structopt(name = "ls")]
    /// List WireGuard persistent keepalives
    List,
}

#[derive(StructOpt, Debug)]
enum ProviderCommand {
    #[structopt(name = "ls")]
    /// List providers
    List,
}

#[derive(StructOpt, Debug)]
enum AddressCommand {
    #[structopt(name = "ls")]
    /// List addresses
    List,

    #[structopt(name = "add")]
    /// Add address
    Add {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,

        /// The network for this address
        #[structopt(name = "NETWORK")]
        network: String,

        /// The address
        #[structopt(name = "ADDRESS")]
        address: Ipv4Addr,

        /// SSH port
        ///
        /// If one is not provided, DEFAULT_SSH_PORT will be used from the environment.
        #[structopt(long)]
        ssh_port: Option<u16>,

        /// WireGuard port
        ///
        /// If one is not provided, DEFAULT_WIREGUARD_PORT will be used from the environment.
        #[structopt(long)]
        wireguard_port: Option<u16>,
    },

    #[structopt(name = "rm")]
    /// Remove address
    Remove {
        /// Machine hostname
        #[structopt(name = "HOSTNAME")]
        hostname: String,

        /// The network
        #[structopt(name = "NETWORK")]
        network: String,

        /// The address
        #[structopt(name = "ADDRESS")]
        address: Ipv4Addr,
    }
}

fn run() -> Result<()> {
    import_env()?;
    env_logger::init();
    let connection = establish_connection()?;

    let matches = InfrabaseCommand::from_args();
    match matches {
        InfrabaseCommand::Provider(cmd) => {
            match cmd {
                ProviderCommand::List => list_providers(&connection)?,
            }
        },
        InfrabaseCommand::Address(cmd) => {
            match cmd {
                AddressCommand::List => list_addresses(&connection)?,
                AddressCommand::Add { hostname, network, address, ssh_port, wireguard_port } => {
                    add_address(&connection, &hostname, &network, address, ssh_port, wireguard_port)?
                },
                AddressCommand::Remove { hostname, network, address } => {
                    remove_address(&connection, &hostname, &network, address)?
                },
            }
        },
        InfrabaseCommand::WireguardKeepalive(cmd) => {
            match cmd {
                WireguardKeepaliveCommand::List => list_wireguard_keepalives(&connection)?,
            }
        },
        InfrabaseCommand::WireguardPrivkey { hostname } => {
            print_wireguard_privkey(&connection, &hostname)?;
        },
        InfrabaseCommand::WriteWireguardPeers => {
            write_wireguard_peers(&connection)?;
        },
        InfrabaseCommand::List => {
            list_machines(&connection)?;
        },
        InfrabaseCommand::NixData => {
            nix_data(&connection)?;
        },
        InfrabaseCommand::Add { hostname, owner, ssh_port, ssh_user, wireguard_ip, wireguard_port, provider, provider_reference } => {
            add_machine(&connection, &hostname, owner, ssh_port, ssh_user, wireguard_ip, wireguard_port, provider, provider_reference)?;
        },
        InfrabaseCommand::Remove { hostname } => {
            remove_machine(&connection, &hostname)?;
        },
        InfrabaseCommand::SshConfig { r#for } => {
            print_ssh_config(&connection, &r#for)?;
        },
        InfrabaseCommand::WgQuick { r#for } => {
            print_wg_quick(&connection, &r#for)?;
        },
    }
    Ok(())
}

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("An error occurred:\n{}", err);
            if let Some(bt) = err.backtrace() {
                eprintln!("{}", bt);
            }
            1
        },
    });
}

#[cfg(test)]
mod tests {
    use super::increment_ip;
    use std::net::Ipv4Addr;

    #[test]
    fn test_increment_ip() {
        assert_eq!(increment_ip(&Ipv4Addr::new(0,   0,   0,   0)),   Some(Ipv4Addr::new(0, 0, 0,   1)));
        assert_eq!(increment_ip(&Ipv4Addr::new(0,   0,   0,   1)),   Some(Ipv4Addr::new(0, 0, 0,   2)));
        assert_eq!(increment_ip(&Ipv4Addr::new(0,   0,   1,   255)), Some(Ipv4Addr::new(0, 0, 2,   0)));
        assert_eq!(increment_ip(&Ipv4Addr::new(0,   0,   255, 0)),   Some(Ipv4Addr::new(0, 0, 255, 1)));
        assert_eq!(increment_ip(&Ipv4Addr::new(0,   2,   255, 255)), Some(Ipv4Addr::new(0, 3, 0,   0)));
        assert_eq!(increment_ip(&Ipv4Addr::new(3,   255, 255, 255)), Some(Ipv4Addr::new(4, 0, 0,   0)));
        assert_eq!(increment_ip(&Ipv4Addr::new(255, 255, 255, 255)), None);
    }
}
