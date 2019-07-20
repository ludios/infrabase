pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;
use structopt::StructOpt;

use models::Machine;
use schema::machines::dsl::*;

fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn print_machines() {
    let connection = establish_connection();

    let results = machines
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    for machine in results {
        println!("{:?}", machine);
    }
}

fn print_ssh_config() {
    let connection = establish_connection();

    // TODO: aggregate addresses
    let results = machines
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    // TODO: get the network of current machine
    // Use that network to determine IP to use for each machine

    for machine in results {
        println!("Host {}", machine.hostname);
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "infrabase")]
/// the machine inventory system
enum Opt {
    #[structopt(name = "ssh_config")]
    /// Prints an ~/.ssh/config that lists all machines
    SshConfig {},
}

fn main() {
    let matches = Opt::from_args();

    match matches {
        Opt::SshConfig {} => {
            print_ssh_config();
        }
    }
}
