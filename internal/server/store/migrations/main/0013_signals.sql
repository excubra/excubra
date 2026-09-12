-- ADR-0018 §7: live detection. The switch per site is on by default — a box that
-- listens harms nobody — and a box reports which decoy ports it has armed.
ALTER TABLE sites ADD COLUMN canary_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE boxes ADD COLUMN canary TEXT NOT NULL DEFAULT '[]';
