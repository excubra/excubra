-- A source is an application that reports itself (ADR-0023). Its token is bound
-- to the source's device and can post that device's events, nothing else. Empty
-- for every operator token.
ALTER TABLE api_tokens ADD COLUMN device_id TEXT NOT NULL DEFAULT '';
