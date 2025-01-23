CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL,
    username VARCHAR(256) NOT NULL,
    groupname VARCHAR(256) NOT NULL,
    event VARCHAR(40) NOT NULL,        
    path VARCHAR(4096) NOT NULL,
    path_secondary VARCHAR(4096) DEFAULT NULL,
);

CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
