-- ADR-0024: a customer LAN on addresses outside RFC 1918.
-- The box reports the directly attached IPv4 networks that are not private in a
-- list of their own: seen, never switched on by themselves.
ALTER TABLE boxes ADD COLUMN lan_other TEXT NOT NULL DEFAULT '[]';
-- An operator declares such a network to be the site's own. From then on remote
-- access, the rules and the DNS sensor treat it like any private LAN.
ALTER TABLE sites ADD COLUMN local_nets TEXT NOT NULL DEFAULT '[]';
