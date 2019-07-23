#![feature(proc_macro_hygiene)]

pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate log;

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

fn print_ssh_config() {
    let connection = establish_connection();

    let machines_ = machines::table
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    let addresses_ = MachineAddress::belonging_to(&machines_)
        .load::<MachineAddress>(&connection)
        .expect("Error loading addresses")
        .grouped_by(&machines_);

    let data = machines_.into_iter().zip(addresses_).collect::<Vec<_>>();

    // TODO: get the network of current machine
    // Use that network to determine IP to use for each machine

    for (machine, addresses) in data {
        println!("# {}'s", machine.owner);
        let address = match *addresses {
            [MachineAddress { address, .. }] => format!("{}", address.ip()),
            _ => "".into(),
        };
        println!(indoc!("
            Host {}
              HostName {}
              Port {}
        "), machine.hostname, address, machine.ssh_port);
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "infrabase")]
/// the machine inventory system
enum Opt {
    #[structopt(name = "ssh_config")]
    /// Prints an ~/.ssh/config that lists all machines
    SshConfig,
}

fn main() {
    import_env();
    env_logger::init();

    let matches = Opt::from_args();
    match matches {
        Opt::SshConfig => {
            print_ssh_config();
        }
    }
}
