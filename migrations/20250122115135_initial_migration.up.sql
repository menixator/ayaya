CREATE TABLE events (
    event VARCHAR(40) NOT NULL,               
    path VARCHAR(4096) NOT NULL,      
    path_secondary VARCHAR(4096), 
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_id_timestamp ON events(id, timestamp);
