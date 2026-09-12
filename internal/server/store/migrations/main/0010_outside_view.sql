-- ADR-0018, the outside view. The server learns each box's public address from
-- the heartbeat's source; an outpost (a box with role 'outpost' in our own
-- infrastructure) scans those addresses; what it sees hangs on one device per
-- site that stands for the site's public address.
ALTER TABLE boxes ADD COLUMN public_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN role TEXT NOT NULL DEFAULT 'box';
ALTER TABLE devices ADD COLUMN external INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_rounds ADD COLUMN external INTEGER NOT NULL DEFAULT 0;
