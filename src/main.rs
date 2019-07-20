pub mod schema;
pub mod models;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;

use models::Machine;
use schema::machines::dsl::*;

fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

fn main() {
    let connection = establish_connection();

    let results = machines
        .limit(5)
        .load::<Machine>(&connection)
        .expect("Error loading machines");

    for machine in results {
        dbg!(machine);
    }
}
