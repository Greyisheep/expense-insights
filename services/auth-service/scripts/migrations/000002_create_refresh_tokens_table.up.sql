CREATE TABLE "refresh_tokens" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "token_hash" varchar UNIQUE NOT NULL,
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "revoked" boolean DEFAULT false,
  "replaced_by" uuid REFERENCES "refresh_tokens" ("id") ON DELETE SET NULL
);

CREATE INDEX ON "refresh_tokens" ("token_hash");
CREATE INDEX ON "refresh_tokens" ("user_id"); 