-- Tasks the console queues for a box (ADR-0014). The box pulls them with its config,
-- runs each exactly once and reports the result in its next heartbeat. A task the box
-- never picked up expires; done tasks are kept for a while as history.
CREATE TABLE box_tasks (
  id         TEXT PRIMARY KEY,
  box_id     TEXT NOT NULL,
  kind       TEXT NOT NULL,
  issued_at  TEXT NOT NULL,
  issued_by  TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  done_at    TEXT,
  ok         INTEGER,
  detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX box_tasks_box ON box_tasks(box_id, issued_at);

-- Lines the agent wants an operator to see (heartbeat notes): a rollback, a refused
-- update, a NetBird failure. Per box, trimmed to the newest 50.
CREATE TABLE box_notes (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  box_id TEXT NOT NULL,
  at     TEXT NOT NULL,
  text   TEXT NOT NULL
);
CREATE INDEX box_notes_box ON box_notes(box_id, id);

-- An operator has seen a problem and says so. Keyed by the problem, not the object:
-- since = start of the outage, so a new outage of the same host is not acknowledged.
CREATE TABLE acks (
  kind      TEXT NOT NULL,
  target_id TEXT NOT NULL,
  since     TEXT NOT NULL,
  actor     TEXT NOT NULL,
  at        TEXT NOT NULL,
  note      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (kind, target_id)
);
