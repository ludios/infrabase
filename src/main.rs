#![deny(unsafe_code)]
#![feature(proc_macro_hygiene)]

mod wireguard;
mod nix;
mod table_cell;
#[macro_use] mod macros;

#[macro_use] extern crate itertools;
#[macro_use] extern crate runtime_fmt;

use std::iter;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::Write;
use std::fs::File;
use std::str;
use std::string::ToString;
use std::convert::TryFrom;
use tabwriter::TabWriter;
use postgres::{Client, Transaction, NoTls};
use dotenv;
use anyhow::{ensure, anyhow, bail, Context, Result};
use structopt::StructOpt;
use indoc::indoc;
use natural_sort::HumanStr;
use itertools::Itertools;
use chrono::{DateTime, Utc};

use nix::ToNix;
use table_cell::ToTableCell;

fn import_env() -> Result<()> {
    let path = dirs::config_dir().unwrap().join("infrabase").join("env");
    dotenv::from_path(&path)
        .with_context(|| format!("Unable to read configuration from {:?}", &path))
}

fn postgres_client() -> Result<Client> {
    let database_url = env_var("DATABASE_URL")?;
    Ok(Client::connect(&database_url, NoTls)?)
}

#[derive(Debug)]
pub struct Machine {
    pub hostname: String,
    pub wireguard_ipv4_address: Option<Ipv4Addr>,
    pub wireguard_ipv6_address: Option<Ipv6Addr>,
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

/// A map of hostname -> Machine
type MachinesMap = HashMap<String, Machine>;

/// A map of (network, other_network) -> priority
type NetworkLinksPriorityMap = HashMap<(String, String), i32>;

/// A map of (source_machine, target_machine) -> interval
type WireguardKeepaliveIntervalMap = HashMap<(String, String), i32>;

fn get_network_links_priority_map(transaction: &mut Transaction) -> Result<NetworkLinksPriorityMap> {
    let map = transaction.query("SELECT name, other_network, priority FROM network_links", &[])?
        .into_iter()
        .map(|row| ((row.get(0), row.get(1)), row.get(2)))
        .collect::<HashMap<_, _>>();
    Ok(map)
}

fn get_wireguard_keepalive_map(transaction: &mut Transaction) -> Result<WireguardKeepaliveIntervalMap> {
    let map = transaction.query("SELECT source_machine, target_machine, interval_sec FROM wireguard_keepalives", &[])?
        .into_iter()
        .map(|row| ((row.get(0), row.get(1)), row.get(2)))
        .collect::<HashMap<_, _>>();
    Ok(map)
}

/// Get IPv4Addr from IpAddr or panic
fn get_ipv4addr(ipaddr: IpAddr) -> Ipv4Addr {
    match ipaddr {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("Got Ipv6Addr: {:?}", ipaddr),
    }
}

/// Get IPv6Addr from IpAddr or panic
fn get_ipv6addr(ipaddr: IpAddr) -> Ipv6Addr {
    match ipaddr {
        IpAddr::V6(ip) => ip,
        IpAddr::V4(_) => panic!("Got Ipv4Addr: {:?}", ipaddr),
    }
}

fn get_machines_with_addresses(transaction: &mut Transaction) -> Result<MachinesMap> {
    let mut machines = HashMap::new();
    for row in transaction.query(
        "SELECT hostname, wireguard_ipv4_address, wireguard_ipv6_address, wireguard_port, wireguard_privkey, wireguard_pubkey,
                ssh_port, ssh_user, added_time, owner, provider_id, provider_reference, networks
         FROM machines_view", &[]
    )? {
        let wireguard_ipv4_address_ipaddr: Option<IpAddr> = row.get(1);
        let wireguard_ipv6_address_ipaddr: Option<IpAddr> = row.get(2);
        let wireguard_ipv4_address = wireguard_ipv4_address_ipaddr.map(get_ipv4addr);
        let wireguard_ipv6_address = wireguard_ipv6_address_ipaddr.map(get_ipv6addr);
        let machine = Machine {
            hostname: row.get(0),
            wireguard_ipv4_address,
            wireguard_ipv6_address,
            wireguard_port: row.get(3),
            wireguard_privkey: row.get(4),
            wireguard_pubkey: row.get(5),
            ssh_port: row.get(6),
            ssh_user: row.get(7),
            added_time: row.get(8),
            owner: row.get(9),
            provider_id: row.get(10),
            provider_reference: row.get(11),
            networks: row.get(12),
            addresses: vec![],
        };
        machines.insert(machine.hostname.clone(), machine);
    }
    for row in transaction.query(
        "SELECT hostname, network, address, ssh_port, wireguard_port
         FROM machine_addresses", &[]
    )? {
        let address = MachineAddress {
            hostname: row.get(0),
            network: row.get(1),
            address: row.get(2),
            ssh_port: row.get(3),
            wireguard_port: row.get(4),
        };
        let machine = machines
            .get_mut(&address.hostname)
            .expect("Database gave us an address for a machine that doesn't exist");
        machine.addresses.push(address);
    }
    Ok(machines)
}

fn print_tabwriter(tw: TabWriter<Vec<u8>>) -> Result<()> {
    let bytes = tw.into_inner()?;
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

/// Write a table header to a TabWriter
fn write_column_names(tw: &mut TabWriter<Vec<u8>>, headers: Vec<&str>) -> Result<()> {
    tw.write_all(headers.join("\t").as_bytes())?;
    tw.write_all(b"\n")?;
    tw.write_all(headers.iter().map(|h| str::repeat("-", h.len())).join("\t").as_bytes())?;
    tw.write_all(b"\n")?;
    Ok(())
}

fn list_providers(transaction: &mut Transaction) -> Result<()> {
    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["ID", "NAME", "EMAIL"])?;
    for row in transaction.query("SELECT id, name, email FROM providers", &[])? {
        let id: i32 = row.get(0);
        let name: String = row.get(1);
        let email: String = row.get(2);
        writeln!(tw, "{}\t{}\t{}", id, name, email)?;
    }
    print_tabwriter(tw)
}

fn list_wireguard_keepalives(transaction: &mut Transaction) -> Result<()> {
    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["SOURCE", "TARGET", "INTERVAL"])?;
    for row in transaction.query("SELECT source_machine, target_machine, interval_sec FROM wireguard_keepalives", &[])? {
        let source_machine: String = row.get(0);
        let target_machine: String = row.get(1);
        let interval_sec: i32 = row.get(2);
        writeln!(tw, "{}\t{}\t{}", source_machine, target_machine, interval_sec)?;
    }
    print_tabwriter(tw)
}

fn add_address(
    mut transaction: Transaction,
    hostname: &str,
    network: &str,
    address: &IpAddr,
    ssh_port: Option<u16>,
    wireguard_port: Option<u16>
) -> Result<()> {
    let ssh_port = unwrap_or_else!(
        ssh_port,
        env_var("DEFAULT_SSH_PORT")?.parse::<u16>()
            .context("Could not parse DEFAULT_SSH_PORT as a u16")?
    );
    let wireguard_port = unwrap_or_else!(
        wireguard_port,
        env_var("DEFAULT_WIREGUARD_PORT")?.parse::<u16>()
            .context("Could not parse DEFAULT_WIREGUARD_PORT as a u16")?
    );
    transaction.execute(
        "INSERT INTO machine_addresses (hostname, network, address, ssh_port, wireguard_port)
         VALUES ($1::varchar, $2::varchar, $3::inet, $4::integer, $5::integer)",
        &[&hostname, &network, &address, &i32::from(ssh_port), &i32::from(wireguard_port)],
    )?;
    transaction.commit()?;
    Ok(())
}

fn remove_address(mut transaction: Transaction, hostname: &str, network: &str, address: &IpAddr) -> Result<()> {
    let num_deleted = transaction.execute(
        "DELETE FROM machine_addresses WHERE hostname = $1 AND network = $2 AND address = $3",
        &[&hostname, &network, &address],
    )?;
    ensure!(num_deleted == 1, "Could not find address ({:?}, {:?}, {:?}) in database", hostname, network, address);
    transaction.commit()?;
    Ok(())
}

fn list_addresses(transaction: &mut Transaction) -> Result<()> {
    let mut addresses = vec![];
    for row in transaction.query("SELECT hostname, network, address, ssh_port, wireguard_port FROM machine_addresses", &[])? {
        addresses.push(MachineAddress {
            hostname: row.get(0),
            network: row.get(1),
            address: row.get(2),
            ssh_port: row.get(3),
            wireguard_port: row.get(4),
        });
    }

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
                 address.ssh_port.to_cell(),
                 address.wireguard_port.to_cell(),
        )?;
    }
    print_tabwriter(tw)
}

/// Convert a MachinesMap to a Vec of &Machine naturally sorted by hostname
fn get_sorted_machines(machines_map: &MachinesMap) -> Vec<&Machine> {
    let mut machines = machines_map
        .iter()
        .map(|(_, machine)| machine)
        .collect::<Vec<_>>();
    // natural_sort refuses to compare string segments with integer segments,
    // so if returns None, fall back to String cmp.
    machines.sort_unstable_by(|m1, m2| {
        HumanStr::new(&m1.hostname)
            .partial_cmp(&HumanStr::new(&m2.hostname))
            .unwrap_or_else(|| m1.hostname.cmp(&m2.hostname))
    });
    machines
}

fn list_machines(mut transaction: &mut Transaction) -> Result<()> {
    let machines_map = get_machines_with_addresses(&mut transaction)?;
    let machines = get_sorted_machines(&machines_map);
    let mut tw = TabWriter::new(vec![]);
    write_column_names(&mut tw, vec!["HOSTNAME", "WG IPV4", "WG IPV6", "OWNER", "PROV", "REFERENCE", "ADDRESSES"])?;
    for machine in machines.into_iter() {
        writeln!(tw, "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                 machine.hostname,
                 &machine.wireguard_ipv4_address.to_cell(),
                 &machine.wireguard_ipv6_address.to_cell(),
                 machine.owner,
                 machine.provider_id.to_cell(),
                 &machine.provider_reference.to_cell(),
                 machine.addresses.iter().map(|a| {
                     format!("{}={}", a.network, a.address)
                 }).join(" ")
        )?;
    }
    print_tabwriter(tw)
}

fn format_nix_address(address: &MachineAddress) -> String {
    format!("{} = {{ ip = {}; ssh_port = {}; wireguard_port = {}; }}; ",
            address.network,
            address.address.to_nix(),
            address.ssh_port.to_nix(),
            address.wireguard_port.to_nix()
    )
}

fn nix_data(mut transaction: &mut Transaction) -> Result<()> {
    let machines_map = get_machines_with_addresses(&mut transaction)?;
    let machines = get_sorted_machines(&machines_map);

    println!("{{");
    let mut tw = TabWriter::new(vec![]).padding(1);
    for machine in machines.into_iter() {
        writeln!(tw, "  {}\t= {{ owner = {};\twireguard_ipv4_address = {};\twireguard_ipv6_address = {};\twireguard_port = {};\tssh_port = {};\tprovider_id = {};\tprovider_reference = {};\taddresses = {{ {}}}; }};",
                 machine.hostname,
                 machine.owner.to_nix(),
                 &machine.wireguard_ipv4_address.to_nix(),
                 &machine.wireguard_ipv6_address.to_nix(),
                 machine.wireguard_port.to_nix(),
                 machine.ssh_port.to_nix(),
                 &machine.provider_id.to_nix(),
                 &machine.provider_reference.to_nix(),
                 machine.addresses.iter().map(format_nix_address).join("")
        )?;
    }
    print_tabwriter(tw)?;
    println!("}}");
    Ok(())
}

fn print_wireguard_privkey(transaction: &mut Transaction, hostname: &str) -> Result<()> {
    let rows = transaction.query("SELECT hostname, wireguard_privkey FROM machines_view WHERE hostname = $1", &[&hostname])?;
    ensure!(!rows.is_empty(), "Could not find machine {:?} in database", hostname);
    let row = &rows[0];
    let privkey: Option<&str> = row.get(1);
    ensure!(privkey.is_some(), "Machine {:?} does not have WireGuard IP", hostname);
    println!("{}", privkey.unwrap());
    Ok(())
}

fn get_existing_wireguard_ipv4_addresses(transaction: &mut Transaction) -> Result<impl Iterator<Item=Ipv4Addr>> {
    let iter = transaction.query("SELECT wireguard_ipv4_address FROM wireguard_interfaces", &[])?
        .into_iter()
        .filter_map(|row| {
            let wireguard_ipaddr: Option<IpAddr> = row.get(0);
            wireguard_ipaddr.map(get_ipv4addr)
        });
    Ok(iter)
}

fn get_existing_wireguard_ipv6_addresses(transaction: &mut Transaction) -> Result<impl Iterator<Item=Ipv6Addr>> {
    let iter = transaction.query("SELECT wireguard_ipv6_address FROM wireguard_interfaces", &[])?
        .into_iter()
        .filter_map(|row| {
            let wireguard_ipaddr: Option<IpAddr> = row.get(0);
            wireguard_ipaddr.map(get_ipv6addr)
        });
    Ok(iter)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn increment_ipv4_address(ip: &Ipv4Addr) -> Option<Ipv4Addr> {
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

fn increment_ipv6_address(ip: &Ipv6Addr) -> Option<Ipv6Addr> {
    let mut segments = ip.segments();
    if segments == [0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff] {
        return None;
    }
    for i in (0..8).rev() {
        if segments[i] < 0xffff {
            segments[i] += 1;
            break;
        } else {
            segments[i] = 0;
        }
    }
    Some(Ipv6Addr::new(segments[0], segments[1], segments[2], segments[3], segments[4], segments[5], segments[6], segments[7]))
}

fn get_unused_wireguard_ipv4_address(mut transaction: &mut Transaction, start_ip: Ipv4Addr, end_ip: Ipv4Addr) -> Result<Option<Ipv4Addr>> {
    let existing = get_existing_wireguard_ipv4_addresses(&mut transaction)?.collect::<HashSet<Ipv4Addr>>();
    let ip_iter = iter::successors(Some(start_ip), increment_ipv4_address);
    for proposed_ip in ip_iter {
        if !existing.contains(&proposed_ip) {
            return Ok(Some(proposed_ip));
        }
        if proposed_ip == end_ip {
            break;
        }
    }
    Ok(None)
}

fn get_unused_wireguard_ipv6_address(mut transaction: &mut Transaction, start_ip: Ipv6Addr, end_ip: Ipv6Addr) -> Result<Option<Ipv6Addr>> {
    let existing = get_existing_wireguard_ipv6_addresses(&mut transaction)?.collect::<HashSet<Ipv6Addr>>();
    let ip_iter = iter::successors(Some(start_ip), increment_ipv6_address);
    for proposed_ip in ip_iter {
        if !existing.contains(&proposed_ip) {
            return Ok(Some(proposed_ip));
        }
        if proposed_ip == end_ip {
            break;
        }
    }
    Ok(None)
}

fn env_var(var: &str) -> Result<String> {
    env::var(var).with_context(|| anyhow!("Could not get variable {:?} from environment", var))
}

#[allow(clippy::too_many_arguments)]
fn add_machine(
    mut transaction: Transaction,
    hostname: &str,
    owner: Option<String>,
    ssh_port: Option<u16>,
    ssh_user: Option<String>,
    wireguard_ipv4_address: Option<Ipv4Addr>,
    wireguard_ipv6_address: Option<Ipv6Addr>,
    wireguard_port: Option<u16>,
    provider: Option<i32>,
    provider_reference: Option<String>,
) -> Result<()> {
    // Required environmental variables
    let ipv4_start = env_var("WIREGUARD_IPV4_START")?.parse::<Ipv4Addr>().context("Could not parse WIREGUARD_IPV4_START as an Ipv4Addr")?;
    let ipv4_end   = env_var("WIREGUARD_IPV4_END")  ?.parse::<Ipv4Addr>().context("Could not parse WIREGUARD_IPV4_END as an Ipv4Addr")?;
    let ipv6_start = env_var("WIREGUARD_IPV6_START")?.parse::<Ipv6Addr>().context("Could not parse WIREGUARD_IPV6_START as an Ipv6Addr")?;
    let ipv6_end   = env_var("WIREGUARD_IPV6_END")  ?.parse::<Ipv6Addr>().context("Could not parse WIREGUARD_IPV6_END as an Ipv6Addr")?;

    // Optional environmental variables
    let ssh_port = unwrap_or_else!(
        ssh_port,
        env_var("DEFAULT_SSH_PORT")
            .context("No SSH user was provided, and could not get variable \"DEFAULT_SSH_PORT\" from environment")?
            .parse::<u16>()
            .context("No SSH port was provided, and could not parse DEFAULT_SSH_PORT as a u16")?
    );
    let ssh_user = unwrap_or_else!(
        ssh_user,
        env_var("DEFAULT_SSH_USER")
            .context("No SSH user was provided, and could not get variable \"DEFAULT_SSH_USER\" from environment")?
    );
    let wireguard_port = unwrap_or_else!(
        wireguard_port,
        env_var("DEFAULT_WIREGUARD_PORT")
            .context("No WireGuard port was provided, and could not get variable \"DEFAULT_WIREGUARD_PORT\" from environment")?
            .parse::<u16>()
            .context("No WireGuard port was provided, and could not parse DEFAULT_WIREGUARD_PORT as a u16")?
    );
    let owner = unwrap_or_else!(
        owner,
        env_var("DEFAULT_OWNER")
            .context("No owner was provided, and could not get variable \"DEFAULT_OWNER\" from environment")?
    );
    let provider_id = ok_or_else!(
        provider,
        match env_var("DEFAULT_PROVIDER") {
            Ok(s) => Some(s.parse::<i32>().context("Could not parse DEFAULT_PROVIDER as an i32")?),
            Err(_) => None,
        }
    );

    let wireguard_ipv4_address = match wireguard_ipv4_address {
        Some(ip) => ip,
        None => {
            get_unused_wireguard_ipv4_address(&mut transaction, ipv4_start, ipv4_end)?
                .context("Could not find an unused WireGuard IPv4 address between WIREGUARD_IPV4_START and WIREGUARD_IPV4_END")?
        }
    };
    let wireguard_ipv6_address = match wireguard_ipv6_address {
        Some(ip) => ip,
        None => {
            get_unused_wireguard_ipv6_address(&mut transaction, ipv6_start, ipv6_end)?
                .context("Could not find an unused WireGuard IPv6 address between WIREGUARD_IPV6_START and WIREGUARD_IPV6_END")?
        }
    };
    let keypair = wireguard::generate_keypair()?;

    transaction.execute(
        "INSERT INTO machines (hostname, owner, provider_id, provider_reference)
                VALUES ($1::varchar, $2::varchar, $3, $4)",
        &[&hostname, &owner, &provider_id, &provider_reference]
    )?;
    transaction.execute(
        "INSERT INTO ssh_servers (hostname, ssh_port, ssh_user)
                VALUES ($1::varchar, $2::integer, $3::varchar)",
        &[&hostname, &i32::from(ssh_port), &ssh_user]
    )?;
    transaction.execute(
        "INSERT INTO wireguard_interfaces (hostname, wireguard_ipv4_address, wireguard_ipv6_address, wireguard_port, wireguard_privkey, wireguard_pubkey)
                VALUES ($1::varchar, $2::inet, $3::inet, $4::integer, $5::varchar, $6::varchar)",
        &[&hostname, &IpAddr::V4(wireguard_ipv4_address), &IpAddr::V6(wireguard_ipv6_address), &i32::from(wireguard_port), &str::from_utf8(&keypair.privkey).unwrap(), &str::from_utf8(&keypair.pubkey).unwrap()]
    )?;
    transaction.commit()?;

    Ok(())
}

fn remove_machine(mut transaction: Transaction, hostname: &str) -> Result<()> {
    transaction.execute("call remove_machine($1)", &[&hostname])?;
    transaction.commit()?;
    Ok(())
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

fn print_ssh_config(mut transaction: &mut Transaction, for_machine: &str) -> Result<()> {
    let machines_map = get_machines_with_addresses(&mut transaction)?;
    let source_machine =
        &machines_map.get(for_machine)
        .ok_or_else(|| anyhow!("machines_map missing {}", for_machine))?;
    let network_links_priority_map = get_network_links_priority_map(&mut transaction)?;
    let machines = get_sorted_machines(&machines_map);

    println!("# infrabase-generated SSH config for {}\n", for_machine);

    for machine in machines.into_iter() {
        let network_to_network = get_network_to_network(&network_links_priority_map, &source_machine.networks, &machine.addresses);
        let (address, ssh_port) = match network_to_network.get(0) {
            None => {
                // We prefer to SSH over the non-WireGuard IP in case WireGuard is down,
                // but if there is no reachable address, use the WireGuard IP instead.
                (machine.wireguard_ipv4_address.map(IpAddr::V4), machine.ssh_port)
            },
            Some((_, dest_network)) => {
                let desired_address = machine.addresses.iter().find(|a| a.network == **dest_network).unwrap();
                (Some(desired_address.address), desired_address.ssh_port)
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

struct WireguardPeer {
    hostname: String,
    wireguard_pubkey: String,
    wireguard_ipv4_address: Ipv4Addr,
    wireguard_ipv6_address: Ipv6Addr,
    endpoint: Option<(IpAddr, u16)>,
    keepalive: Option<i32>,
}

/// Get a list of WireGuard peers for a machine, taking into account the source
/// and destination networks for each machine-machine pair.
#[allow(clippy::ptr_arg)]
fn get_wireguard_peers(
    machines_map: &MachinesMap,
    network_links_priority_map: &NetworkLinksPriorityMap,
    keepalives_map: &WireguardKeepaliveIntervalMap,
    for_machine: &str,
) -> Result<Vec<WireguardPeer>> {
    let mut peers = vec![];
    let source_machine =
        &machines_map.get(for_machine)
        .ok_or_else(|| anyhow!("machines_map missing {}", for_machine))?;
    for machine in machines_map.values() {
        if machine.hostname == for_machine {
            // We don't need a [Peer] for ourselves
            continue;
        }
        let network_to_network = get_network_to_network(&network_links_priority_map, &source_machine.networks, &machine.addresses);
        let endpoint = match network_to_network.get(0) {
            Some((_, dest_network)) => {
                let desired_address = machine.addresses.iter().find(|a| a.network == *dest_network);
                match desired_address {
                    Some(MachineAddress { address, wireguard_port: Some(port), .. }) => {
                        Some((*address, u16::try_from(*port)
                            .with_context(|| anyhow!("Port {} out of expected range 0-65535", *port))?))
                    },
                    _ => None,
                }
            },
            None => None,
        };

        // If we have a wireguard peer
        if let (Some(wireguard_ipv4_address),
                Some(wireguard_ipv6_address),
                Some(wireguard_pubkey)) = (machine.wireguard_ipv4_address, machine.wireguard_ipv6_address, &machine.wireguard_pubkey) {
            let keepalive = keepalives_map.get(&(for_machine.to_string(), machine.hostname.to_string())).copied();
            peers.push(WireguardPeer {
                hostname: machine.hostname.clone(),
                wireguard_pubkey: wireguard_pubkey.clone(),
                wireguard_ipv4_address,
                wireguard_ipv6_address,
                endpoint,
                keepalive,
            });
        }
    }
    Ok(peers)
}

fn sort_wireguard_peers(peers: &mut Vec<WireguardPeer>) {
    peers.sort_unstable_by(|p1, p2| {
        HumanStr::new(&p1.hostname)
            .partial_cmp(&HumanStr::new(&p2.hostname))
            .unwrap()
    });
}

fn print_wg_quick(mut transaction: &mut Transaction, for_machine: &str) -> Result<()> {
    let machines_map = get_machines_with_addresses(&mut transaction)?;
    let network_links_priority_map = get_network_links_priority_map(&mut transaction)?;
    let keepalives_map = get_wireguard_keepalive_map(&mut transaction)?;
    let my_machine = unwrap_or_else!(
        machines_map.get(for_machine),
        bail!("Could not find machine {:?} in database", for_machine)
    );

    ensure!(my_machine.wireguard_ipv4_address.is_some(), "Machine {:?} does not have WireGuard IPv4 address", for_machine);
    ensure!(my_machine.wireguard_ipv6_address.is_some(), "Machine {:?} does not have WireGuard IPv6 address", for_machine);

    println!(indoc!("
        # infrabase-generated wg-quick config for {}

        [Interface]
        Address = {}/32, {}/128
        PrivateKey = {}
        ListenPort = {}
    "),
        for_machine,
        my_machine.wireguard_ipv4_address.unwrap(), my_machine.wireguard_ipv6_address.unwrap(),
        my_machine.wireguard_privkey.as_ref().unwrap(),
        my_machine.wireguard_port.unwrap()
    );

    let mut peers = get_wireguard_peers(&machines_map, &network_links_priority_map, &keepalives_map, for_machine)?;
    sort_wireguard_peers(&mut peers);
    for peer in peers.iter() {
        let maybe_endpoint = match peer.endpoint {
            Some((address, port)) => format!("Endpoint = {}:{}\n", address, port),
            None => "".to_string(),
        };
        let maybe_keepalive = match peer.keepalive {
            Some(interval) => format!("PersistentKeepalive = {}\n", interval),
            None => "".to_string()
        };
        println!(indoc!("
            # {}
            [Peer]
            PublicKey = {}
            AllowedIPs = {}/32, {}/128
            {}\
            {}\
        "),
            peer.hostname,
            peer.wireguard_pubkey,
            peer.wireguard_ipv4_address, peer.wireguard_ipv6_address,
            maybe_endpoint,
            maybe_keepalive
        );
    }
    Ok(())
}

/// Write a .nix file for each machine listing its WireGuard peers
fn write_wireguard_peers(mut transaction: &mut Transaction) -> Result<()> {
    let machines_map = get_machines_with_addresses(&mut transaction)?;
    let network_links_priority_map = get_network_links_priority_map(&mut transaction)?;
    let keepalives_map = get_wireguard_keepalive_map(&mut transaction)?;
    let machines = get_sorted_machines(&machines_map);

    let path_template = env_var("WIREGUARD_PEERS_PATH_TEMPLATE")?;

    for machine in machines.into_iter() {
        let path =
            // Beware https://github.com/SpaceManiac/runtime-fmt/issues/6
            rt_format!(path_template,
                       hostname = &machine.hostname,
                       wireguard_ipv4_address = &machine.wireguard_ipv4_address,
                       wireguard_ipv6_address = &machine.wireguard_ipv6_address)
            .map_err(|_| anyhow!("Bad template in WIREGUARD_PEERS_PATH_TEMPLATE: allowed tokens are \
                                  {hostname}, {wireguard_ipv4_address}, and {wireguard_ipv6_address}"))?;
        let mut file = File::create(path)?;
        file.write_all(b"[\n")?;
        let mut peers = get_wireguard_peers(&machines_map, &network_links_priority_map, &keepalives_map, &machine.hostname)?;
        sort_wireguard_peers(&mut peers);
        for peer in peers.iter() {
            let maybe_endpoint = match peer.endpoint {
                Some((address, port)) => format!("endpoint = \"{}:{}\"; ", address, port),
                None => "".to_string(),
            };
            let maybe_keepalive = match peer.keepalive {
                Some(interval) => format!("persistentKeepalive = {}; ", interval),
                None => "".to_string()
            };
            writeln!(file, "  {{ name = {}; allowedIPs = [ \"{}/32\" \"{}/128\" ]; publicKey = {}; {}{}}}",
                     peer.hostname.to_nix(),
                     peer.wireguard_ipv4_address, peer.wireguard_ipv6_address,
                     peer.wireguard_pubkey.to_nix(),
                     maybe_endpoint,
                     maybe_keepalive)?;
        }
        file.write_all(b"]\n")?;
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

        /// WireGuard IPv4 IP
        ///
        /// If one is not provided, an unused IP address will be selected.
        #[structopt(long)]
        wireguard_ipv4_address: Option<Ipv4Addr>,

        /// WireGuard IPv6 IP
        ///
        /// If one is not provided, an unused IP address will be selected.
        #[structopt(long)]
        wireguard_ipv6_address: Option<Ipv6Addr>,

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
        provider: Option<i32>,

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

    #[structopt(name = "ssh-config")]
    /// Prints an ~/.ssh/config that lists all machines
    SshConfig {
        /// Machine to generate SSH config for
        #[structopt(long = "for", name = "MACHINE")]
        r#for: String,
    },

    #[structopt(name = "wg-quick")]
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
        address: IpAddr,

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
        address: IpAddr,
    }
}

fn main() -> Result<()> {
    import_env()?;
    env_logger::init();
    let mut client = postgres_client()?;
    let mut transaction = client.transaction()?;

    let matches = InfrabaseCommand::from_args();
    match matches {
        InfrabaseCommand::Provider(cmd) => {
            match cmd {
                ProviderCommand::List => list_providers(&mut transaction)?,
            }
        },
        InfrabaseCommand::Address(cmd) => {
            match cmd {
                AddressCommand::List => list_addresses(&mut transaction)?,
                AddressCommand::Add { hostname, network, address, ssh_port, wireguard_port } => {
                    add_address(transaction, &hostname, &network, &address, ssh_port, wireguard_port)?
                },
                AddressCommand::Remove { hostname, network, address } => {
                    remove_address(transaction, &hostname, &network, &address)?
                },
            }
        },
        InfrabaseCommand::WireguardKeepalive(cmd) => {
            match cmd {
                WireguardKeepaliveCommand::List => list_wireguard_keepalives(&mut transaction)?,
            }
        },
        InfrabaseCommand::WireguardPrivkey { hostname } => {
            print_wireguard_privkey(&mut transaction, &hostname)?;
        },
        InfrabaseCommand::WriteWireguardPeers => {
            write_wireguard_peers(&mut transaction)?;
        },
        InfrabaseCommand::List => {
            list_machines(&mut transaction)?;
        },
        InfrabaseCommand::NixData => {
            nix_data(&mut transaction)?;
        },
        InfrabaseCommand::Add { hostname, owner, ssh_port, ssh_user, wireguard_ipv4_address, wireguard_ipv6_address, wireguard_port, provider, provider_reference } => {
            add_machine(transaction, &hostname, owner, ssh_port, ssh_user, wireguard_ipv4_address, wireguard_ipv6_address, wireguard_port, provider, provider_reference)?;
        },
        InfrabaseCommand::Remove { hostname } => {
            remove_machine(transaction, &hostname)?;
        },
        InfrabaseCommand::SshConfig { r#for } => {
            print_ssh_config(&mut transaction, &r#for)?;
        },
        InfrabaseCommand::WgQuick { r#for } => {
            print_wg_quick(&mut transaction, &r#for)?;
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{increment_ipv4_address, increment_ipv6_address};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_increment_ipv4_address() {
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(0,   0,   0,   0)),   Some(Ipv4Addr::new(0, 0, 0,   1)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(0,   0,   0,   1)),   Some(Ipv4Addr::new(0, 0, 0,   2)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(0,   0,   1,   255)), Some(Ipv4Addr::new(0, 0, 2,   0)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(0,   0,   255, 0)),   Some(Ipv4Addr::new(0, 0, 255, 1)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(0,   2,   255, 255)), Some(Ipv4Addr::new(0, 3, 0,   0)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(3,   255, 255, 255)), Some(Ipv4Addr::new(4, 0, 0,   0)));
        assert_eq!(increment_ipv4_address(&Ipv4Addr::new(255, 255, 255, 255)), None);
    }

    #[test]
    fn test_increment_ipv6_address() {
        assert_eq!(increment_ipv6_address(&"0:0:0:0:0:0:0:0"                        .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:0:0:0:1"   .parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"0:0:0:0:0:0:0:1"                        .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:0:0:0:2"   .parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"0:0:0:0:0:0:1:ffff"                     .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:0:0:2:0"   .parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"0:0:0:0:0:0:ffff:0"                     .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:0:0:ffff:1".parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"0:0:0:0:0:2:ffff:ffff"                  .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:0:3:0:0"   .parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"0:0:0:0:3:ffff:ffff:ffff"               .parse::<Ipv6Addr>().unwrap()), Some("0:0:0:0:4:0:0:0"   .parse().unwrap()));
        assert_eq!(increment_ipv6_address(&"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse::<Ipv6Addr>().unwrap()), None);
    }
}
