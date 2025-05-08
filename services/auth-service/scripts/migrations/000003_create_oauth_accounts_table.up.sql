CREATE TABLE "oauth_accounts" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "provider" varchar NOT NULL,
  "provider_user_id" varchar NOT NULL,
  "access_token" varchar,
  "refresh_token" varchar,
  "expires_at" timestamp,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  UNIQUE ("provider", "provider_user_id")
);

CREATE INDEX ON "oauth_accounts" ("user_id"); 