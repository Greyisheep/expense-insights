-- Migration to drop the users table
DROP TABLE IF EXISTS "users";

-- Optionally drop the extension if it's certain no other table needs it
-- DROP EXTENSION IF EXISTS "uuid-ossp"; 