table! {
    machine_addresses (hostname, network, address) {
        hostname -> Varchar,
        network -> Varchar,
        address -> Inet,
        ssh_port -> Nullable<Int4>,
        wireguard_port -> Nullable<Int4>,
    }
}

table! {
    machines (hostname) {
        hostname -> Varchar,
        wireguard_ip -> Nullable<Inet>,
        wireguard_port -> Nullable<Int4>,
        wireguard_privkey -> Nullable<Varchar>,
        wireguard_pubkey -> Nullable<Varchar>,
        ssh_port -> Nullable<Int4>,
        ssh_user -> Nullable<Varchar>,
        added_time -> Timestamptz,
        owner -> Varchar,
        provider_id -> Nullable<Int4>,
    }
}

table! {
    network_links (name, other_network) {
        name -> Varchar,
        other_network -> Varchar,
        priority -> Int4,
    }
}

table! {
    networks (name) {
        name -> Varchar,
    }
}

table! {
    owners (owner) {
        owner -> Varchar,
    }
}

table! {
    providers (id) {
        id -> Int4,
        name -> Varchar,
        email -> Varchar,
    }
}

table! {
    wireguard_persistent_keepalives (source_machine, target_machine) {
        source_machine -> Varchar,
        target_machine -> Varchar,
        interval_sec -> Int4,
    }
}

joinable!(machine_addresses -> machines (hostname));
joinable!(machine_addresses -> networks (network));
joinable!(machines -> owners (owner));
joinable!(machines -> providers (provider_id));

allow_tables_to_appear_in_same_query!(
    machine_addresses,
    machines,
    network_links,
    networks,
    owners,
    providers,
    wireguard_persistent_keepalives,
);
