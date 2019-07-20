CREATE DOMAIN hostname         AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname          AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN port             AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key    AS bytea        CHECK (length(VALUE) = 44);
 -- Match default /etc/adduser.conf NAME_REGEX
CREATE DOMAIN username         AS varchar(32)  CHECK (VALUE ~ '\A[a-z][-a-z0-9_]{1,31}\Z');

CREATE TABLE networks (
	name   netname NOT NULL PRIMARY KEY,
	parent netname REFERENCES networks(name) CHECK (parent != name)
);

CREATE TABLE machines (
	hostname          hostname                 NOT NULL PRIMARY KEY,
	wireguard_ip      inet,
	wireguard_port    port                     CHECK ((wireguard_ip IS NOT NULL AND wireguard_port   IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_port   IS NULL)),
	wireguard_pubkey  wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_pubkey IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_pubkey IS NULL)),
	ssh_port          port                     NOT NULL DEFAULT 904,
	ssh_user          username                 NOT NULL DEFAULT 'root',
	added_time        timestamp with time zone NOT NULL DEFAULT now(),

	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_pubkey)
);

CREATE TABLE machine_addresses (
	hostname hostname NOT NULL REFERENCES machines,
	network  netname  NOT NULL REFERENCES networks(name),
	address  inet     NOT NULL,
	PRIMARY KEY (hostname, network, address),
	UNIQUE (network, address)
);
