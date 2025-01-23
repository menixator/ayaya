-- Drop the index first
DROP INDEX IF EXISTS idx_events_timestamp;

-- Drop the table
DROP TABLE IF EXISTS events CASCADE;
