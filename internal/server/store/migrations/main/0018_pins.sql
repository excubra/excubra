-- What an operator wants in reach. With fifty customers the sidebar's lists stop
-- being a shortcut and become a place to scroll; the three a person is working on
-- today belong at the top instead. Per user, because that is whose day it is.
CREATE TABLE pins (
  user_id   TEXT NOT NULL REFERENCES users(id),
  kind      TEXT NOT NULL, -- tenant | site
  target_id TEXT NOT NULL,
  pinned_at TEXT NOT NULL,
  PRIMARY KEY (user_id, kind, target_id)
);
CREATE INDEX pins_user ON pins(user_id, pinned_at);
