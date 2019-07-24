CREATE DOMAIN hostname       AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname        AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN port           AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key  AS varchar(44)  CHECK (length(VALUE) = 44);
 -- Match default /etc/adduser.conf NAME_REGEX
CREATE DOMAIN username       AS varchar(32)  CHECK (VALUE ~ '\A[a-z][-a-z0-9_]{1,31}\Z');
CREATE DOMAIN email          AS varchar(254) CHECK (VALUE ~ '\A.+@.+\Z');
CREATE DOMAIN owner          AS varchar(32);

-- a tree of networks; sub-network is assumed to be able to reach parent networks
CREATE TABLE networks (
	name    netname NOT NULL PRIMARY KEY,
	parent  netname REFERENCES networks(name) CHECK (parent != name)
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
	hostname          hostname                 NOT NULL PRIMARY KEY,
	wireguard_ip      inet,
	wireguard_pubkey  wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_pubkey IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_pubkey IS NULL)),
	ssh_user          username                 NOT NULL DEFAULT 'root',
	added_time        timestamp with time zone NOT NULL DEFAULT now(),
	owner             owner                    NOT NULL REFERENCES owners(owner),
	provider_id       integer                  REFERENCES providers(id),

	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_pubkey)
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
