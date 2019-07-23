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
        wireguard_pubkey -> Nullable<Varchar>,
        ssh_port -> Int4,
        ssh_user -> Varchar,
        added_time -> Timestamptz,
        owner -> Varchar,
        provider_id -> Nullable<Int4>,
    }
}

table! {
    networks (name) {
        name -> Varchar,
        parent -> Nullable<Varchar>,
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

joinable!(machine_addresses -> machines (hostname));
joinable!(machine_addresses -> networks (network));
joinable!(machines -> owners (owner));
joinable!(machines -> providers (provider_id));

allow_tables_to_appear_in_same_query!(
    machine_addresses,
    machines,
    networks,
    owners,
    providers,
);
