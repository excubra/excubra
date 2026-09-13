-- Where a site actually is, so the console can show fifty of them on a map
-- instead of in a list nobody can scan. The address is free text the operator
-- types; the coordinates are looked up once, in the operator's browser, and
-- stored here so nothing leaves the console again. NULL means "not located yet"
-- — 0/0 is a real place in the Gulf of Guinea and would put a marker there.
ALTER TABLE sites ADD COLUMN address TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN lat REAL;
ALTER TABLE sites ADD COLUMN lon REAL;
