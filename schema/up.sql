CREATE DOMAIN inet4          AS inet         CHECK (family(VALUE) = 4);
CREATE DOMAIN inet6          AS inet         CHECK (family(VALUE) = 6);
CREATE DOMAIN hostname       AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname        AS varchar(32)  CHECK (VALUE ~ '\A(NONE|[-_a-z0-9]+)\Z');
CREATE DOMAIN port           AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key  AS varchar(44)  CHECK (VALUE ~ '\A[+/A-Za-z0-9]{43}=\Z');
-- Match default /etc/adduser.conf NAME_REGEX
CREATE DOMAIN username       AS varchar(32)  CHECK (VALUE ~ '\A[a-z][-a-z0-9_]{1,31}\Z');
CREATE DOMAIN email          AS varchar(254) CHECK (VALUE ~ '\A.+@.+\Z');
CREATE DOMAIN owner          AS varchar(32);

-- INSERT name='NONE' to support machines that have no addresses in machine_addresses
CREATE TABLE networks (
    name  netname NOT NULL PRIMARY KEY
);

-- If network `name` can reach all addresses on `other_network`, it must be listed here
-- Network must also have a self-link if machines on the network can reach other addresses on the network
--
-- priority decides which endpoint should be used when there are multiple candidates
--
-- INSERT (name='NONE', other_network='internet', priority=...) to indicate that machine
-- without any addresses in machine_addresses can reach machines on network 'internet'.
--
-- (internet,  internet,   0)
-- (homelan,   homelan,   -1) <- if machine on homelan reaching another machine on homelan, prefer this over (internet, internet) or (homelan, internet)
-- (homelan,   internet,   0)
-- (work,      work,      -1)
-- (work,      internet,   0)
--
CREATE TABLE network_links (
    name           netname  NOT NULL REFERENCES networks(name),
    other_network  netname  NOT NULL REFERENCES networks(name),
    priority       integer  NOT NULL,
    PRIMARY KEY (name, other_network)
);

-- Hosting accounts
CREATE TABLE providers (
    id     serial       NOT NULL PRIMARY KEY,
    name   varchar(32)  NOT NULL,
    email  email        NOT NULL
);

-- Valid owners
CREATE TABLE owners (
    owner  owner  NOT NULL PRIMARY KEY
);

CREATE TABLE machines (
    hostname            hostname                  NOT NULL PRIMARY KEY,
    added_time          timestamp with time zone  NOT NULL DEFAULT now(),
    owner               owner                     NOT NULL REFERENCES owners(owner),
    provider_id         integer                   REFERENCES providers(id),
    provider_reference  text
);

-- Separate table because not all machines have an infrabase-managed WireGuard interface
CREATE TABLE wireguard_interfaces (
   hostname                hostname       NOT NULL PRIMARY KEY REFERENCES machines,
   wireguard_ipv4_address  inet4          NOT NULL,
   wireguard_ipv6_address  inet6          NOT NULL,
   wireguard_port          port           NOT NULL,
   wireguard_privkey       wireguard_key  NOT NULL,
   wireguard_pubkey        wireguard_key  NOT NULL,
   UNIQUE (wireguard_privkey),
   UNIQUE (wireguard_pubkey)
);

-- Separate table because not all machines have an SSH server
CREATE TABLE ssh_servers (
    hostname  hostname  NOT NULL PRIMARY KEY REFERENCES machines,
    ssh_port  port      NOT NULL,
    ssh_user  username  NOT NULL DEFAULT 'root'
);

CREATE TABLE wireguard_keepalives (
    source_machine  hostname  NOT NULL REFERENCES machines(hostname),
    target_machine  hostname  NOT NULL REFERENCES machines(hostname),
    -- `man wg` says "PersistentKeepalive — a seconds interval, between 1 and 65535 inclusive"
    interval_sec    integer   NOT NULL CHECK (interval_sec >= 1 AND interval_sec <= 65535),
    PRIMARY KEY (source_machine, target_machine)
);

-- Note: you should use a different WireGuard port for each machine behind the same NAT.
--
-- WireGuard remembers just one endpoint per machine and if it gets a packet from IP:904
-- it will assume (IP, 904) is reachable even if the port forward on the router is 905 -> 904
-- and the endpoint was originally configured to use :905

CREATE TABLE machine_addresses (
    hostname        hostname  NOT NULL REFERENCES machines,
    network         netname   NOT NULL REFERENCES networks(name),
    address         inet      NOT NULL,
    ssh_port        port,
    wireguard_port  port,
    PRIMARY KEY (hostname, network, address),
    UNIQUE (address, ssh_port),
    UNIQUE (address, wireguard_port)
);

CREATE VIEW machines_view AS
    SELECT
        machines.hostname,
        added_time,
        owner,
        provider_id,
        providers.name AS provider_name,
        providers.email AS provider_email,
        provider_reference,
        coalesce(networks.networks, ARRAY['NONE']) AS networks,
        wireguard_ipv4_address,
        wireguard_ipv6_address,
        wireguard_port,
        wireguard_privkey,
        wireguard_pubkey,
        ssh_port,
        ssh_user
    FROM machines
    LEFT JOIN wireguard_interfaces ON machines.hostname = wireguard_interfaces.hostname
    LEFT JOIN ssh_servers          ON machines.hostname = ssh_servers.hostname
    LEFT JOIN providers            ON machines.provider_id = providers.id
    LEFT JOIN (SELECT hostname, array_agg(network::varchar) AS networks FROM machine_addresses GROUP BY hostname) networks ON machines.hostname = networks.hostname;

CREATE VIEW providers_count AS
    SELECT count, provider_id, name, email FROM (
        SELECT provider_id, COUNT(*) FROM machines GROUP BY provider_id
    ) AS m
    LEFT JOIN providers ON m.provider_id = id
    ORDER BY count DESC;

-- Remove all mentions of machine from database
CREATE PROCEDURE remove_machine(kill_hostname varchar)
LANGUAGE plpgsql
AS $$
    DELETE FROM wireguard_interfaces WHERE hostname = kill_hostname;
    DELETE FROM ssh_servers          WHERE hostname = kill_hostname;
    DELETE FROM machine_addresses    WHERE hostname = kill_hostname;
    DELETE FROM wireguard_keepalives WHERE source_machine = kill_hostname OR target_machine = kill_hostname;
    DELETE FROM machines             WHERE hostname = kill_hostname;
$$;
