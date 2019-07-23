CREATE DOMAIN hostname       AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname        AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN port           AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key  AS varchar(44)  CHECK (length(VALUE) = 44);
 -- Match default /etc/adduser.conf NAME_REGEX
CREATE DOMAIN username       AS varchar(32)  CHECK (VALUE ~ '\A[a-z][-a-z0-9_]{1,31}\Z');
CREATE DOMAIN email          AS varchar(254) CHECK (VALUE ~ '\A.+@.+\Z');

-- a tree of networks; sub-network is assumed to be able to reach parent networks
CREATE TABLE networks (
	name    netname NOT NULL PRIMARY KEY,
	parent  netname REFERENCES networks(name) CHECK (parent != name)
);

-- hosting accounts
CREATE TABLE providers (
    name   varchar(32) NOT NULL,
    email  email       NOT NULL,
    PRIMARY KEY (name, email)
);

-- who owns the machine?
CREATE TABLE owners (
    owner  varchar(32) NOT NULL PRIMARY KEY
);

CREATE TABLE machines (
	hostname          hostname                 NOT NULL PRIMARY KEY,
	wireguard_ip      inet,
	-- Use a different WireGuard port for each machine behind the same NAT.
	--
	-- wireguard_port is per-machine instead of per-address because of how WireGuard and UDP work:
	-- WireGuard remembers just one endpoint per machine and will assume e.g. (internet IP, 904) is reachable
	-- even if the port forward was 905 -> 904
	wireguard_port    port                     CHECK ((wireguard_ip IS NOT NULL AND wireguard_port   IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_port   IS NULL)),
	wireguard_pubkey  wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_pubkey IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_pubkey IS NULL)),
	ssh_port          port                     NOT NULL DEFAULT 904,
	ssh_user          username                 NOT NULL DEFAULT 'root',
	added_time        timestamp with time zone NOT NULL DEFAULT now(),

	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_pubkey)
);

CREATE TABLE machine_addresses (
	hostname  hostname NOT NULL REFERENCES machines,
	network   netname  NOT NULL REFERENCES networks(name),
	address   inet     NOT NULL,
	PRIMARY KEY (hostname, network, address)
	-- (network, address) isn't necessarily unique; several machines may share the same address but have different ports
);
