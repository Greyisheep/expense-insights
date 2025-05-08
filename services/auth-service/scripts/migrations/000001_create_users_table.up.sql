-- Migration for creating the users table
CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; -- Ensure uuid functions are available

CREATE TABLE "users" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "email" varchar UNIQUE NOT NULL,
  "password_hash" varchar NOT NULL,
  "first_name" varchar NOT NULL,
  "last_name" varchar NOT NULL,
  "phone_number" varchar, -- Nullable
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now()),
  "last_login_at" timestamp, -- Nullable
  "status" varchar NOT NULL DEFAULT 'pending', -- Default to pending until activation/verification if needed
  "role" varchar NOT NULL DEFAULT 'user'
);

CREATE INDEX ON "users" ("email");

COMMENT ON TABLE "users" IS 'User accounts with authentication details and profile information'; 