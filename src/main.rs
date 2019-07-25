#![feature(proc_macro_hygiene)]

pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv;
use std::env;
use structopt::StructOpt;
use indoc::indoc;

use schema::machines;
use models::{Machine, MachineAddress};

fn import_env() {
    let dirs = xdg::BaseDirectories::with_prefix("infrabase").unwrap();
    let path = dirs.find_config_file("env").expect("Could not find ~/.config/infrabase/env");
    dotenv::from_path(&path).ok();
}

fn establish_connection() -> PgConnection {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn print_ssh_config(for_machine: &str) {
    let connection = establish_connection();

    let machines = machines::table
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    let addresses = MachineAddress::belonging_to(&machines)
        .load::<MachineAddress>(&connection)
        .expect("Error loading addresses")
        .grouped_by(&machines);

    let data = machines.into_iter().zip(addresses).collect::<Vec<_>>();

    // TODO: get the network of current machine
    // Use that network to determine IP to use for each machine

    println!("# infrabase-generated SSH config for {}\n", for_machine);

    for (machine, addresses) in data {
        let (address, ssh_port) = match *addresses {
            [MachineAddress { address, ssh_port, .. }] => (format!("{}", address.ip()), ssh_port),
            _ => ("".into(), None),
        };
        if let Some(port) = ssh_port {
            println!(indoc!("
                # {}'s
                Host {}
                  HostName {}
                  Port {}
            "), machine.owner, machine.hostname, address, port);
        }
    }
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

fn main() {
    import_env();
    env_logger::init();

    let matches = Opt::from_args();
    match matches {
        Opt::SshConfig { r#for } => {
            print_ssh_config(&r#for);
        }
    }
}
