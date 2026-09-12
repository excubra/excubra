-- The resource in the operator stack carries the customer's and the site's name,
-- so a technician's client lists "Kunde · Standort", not just a network.
ALTER TABLE remote_access ADD COLUMN resource_name TEXT NOT NULL DEFAULT '';
