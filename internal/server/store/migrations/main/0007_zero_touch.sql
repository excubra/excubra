-- ADR-0017: a box needs nobody after it is plugged in.
-- An enrollment key can be made for a site: the box lands there on enrollment.
ALTER TABLE enrollment_keys ADD COLUMN site_id TEXT;
-- The box reports the networks it sits in; the first one is the site's LAN for
-- remote access, switched on by the server without anyone typing it.
ALTER TABLE boxes ADD COLUMN lan TEXT NOT NULL DEFAULT '[]';
