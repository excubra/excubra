-- ADR-0006 amendment: the capabilities the agent process reports, so the console
-- can tell an installation that predates a release's needs from one that is fine.
ALTER TABLE boxes ADD COLUMN caps TEXT NOT NULL DEFAULT '[]';
