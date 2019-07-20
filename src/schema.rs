table! {
    machine_addresses (hostname, network, address) {
        hostname -> Varchar,
        network -> Varchar,
        address -> Inet,
    }
}

table! {
    machines (hostname) {
        hostname -> Varchar,
        wireguard_ip -> Nullable<Inet>,
        wireguard_port -> Nullable<Int4>,
        wireguard_pubkey -> Nullable<Bytea>,
        ssh_port -> Int4,
        ssh_user -> Varchar,
        added_time -> Timestamptz,
    }
}

table! {
    networks (name) {
        name -> Varchar,
        parent -> Nullable<Varchar>,
    }
}

joinable!(machine_addresses -> machines (hostname));
joinable!(machine_addresses -> networks (network));

allow_tables_to_appear_in_same_query!(
    machine_addresses,
    machines,
    networks,
);
