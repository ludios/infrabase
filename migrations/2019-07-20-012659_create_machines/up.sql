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
    name           netname NOT NULL REFERENCES networks(name),
    other_network  netname NOT NULL REFERENCES networks(name),
    priority       integer NOT NULL,
    PRIMARY KEY (name, other_network)
);

-- hosting accounts
CREATE TABLE providers (
    id     serial      NOT NULL PRIMARY KEY,
    name   varchar(32) NOT NULL,
    email  email       NOT NULL
);

-- who owns the machine?
CREATE TABLE owners (
    owner  owner NOT NULL PRIMARY KEY
);

CREATE TABLE machines (
    hostname           hostname                 NOT NULL PRIMARY KEY,
    wireguard_ip       inet,
    wireguard_port     port                     CHECK ((wireguard_ip IS NOT NULL AND wireguard_port    IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_port    IS NULL)),
    wireguard_privkey  wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_privkey IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_privkey IS NULL)),
    wireguard_pubkey   wireguard_key,           CHECK ((wireguard_ip IS NOT NULL AND wireguard_pubkey  IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_pubkey  IS NULL)),
    ssh_port           port,
    ssh_user           username                 DEFAULT 'root' CHECK ((ssh_port IS NOT NULL AND ssh_user IS NOT NULL) OR (ssh_port IS NULL AND ssh_user IS NULL)),
    added_time         timestamp with time zone NOT NULL DEFAULT now(),
    owner              owner                    NOT NULL REFERENCES owners(owner),
    provider_id        integer                  REFERENCES providers(id),
    provider_reference text,

    UNIQUE (wireguard_ip),
    UNIQUE (wireguard_privkey),
    UNIQUE (wireguard_pubkey)
);

CREATE TABLE wireguard_keepalives (
    source_machine hostname NOT NULL REFERENCES machines(hostname),
    target_machine hostname NOT NULL REFERENCES machines(hostname),
    -- `man wg` says "PersistentKeepalive — a seconds interval, between 1 and 65535 inclusive"
    interval_sec   integer  NOT NULL CHECK (interval_sec >= 1 AND interval_sec <= 65535),
    PRIMARY KEY (source_machine, target_machine)
);

-- Note: you should use a different WireGuard port for each machine behind the same NAT.
--
-- WireGuard remembers just one endpoint per machine and if it gets a packet from IP:904
-- it will assume (IP, 904) is reachable even if the port forward on the router is 905 -> 904
-- and the endpoint was originally configured to use :905

CREATE TABLE machine_addresses (
    hostname       hostname NOT NULL REFERENCES machines,
    network        netname  NOT NULL REFERENCES networks(name),
    address        inet     NOT NULL,
    ssh_port       port,
    wireguard_port port,
    PRIMARY KEY (hostname, network, address),
    UNIQUE (address, ssh_port),
    UNIQUE (address, wireguard_port)
);
