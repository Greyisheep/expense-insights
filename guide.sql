CREATE TABLE "users" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "email" varchar UNIQUE NOT NULL,
  "password_hash" varchar NOT NULL,
  "first_name" varchar NOT NULL,
  "last_name" varchar NOT NULL,
  "phone_number" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "last_login_at" timestamp,
  "status" varchar NOT NULL DEFAULT 'active',
  "role" varchar NOT NULL DEFAULT 'user'
);

CREATE TABLE "refresh_tokens" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "token" varchar UNIQUE NOT NULL,
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "revoked" boolean DEFAULT false,
  "replaced_by" uuid
);

CREATE TABLE "oauth_accounts" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "provider" varchar NOT NULL,
  "provider_user_id" varchar NOT NULL,
  "access_token" varchar,
  "refresh_token" varchar,
  "expires_at" timestamp,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "uploads" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "file_name" varchar NOT NULL,
  "content_type" varchar NOT NULL,
  "status" varchar NOT NULL DEFAULT 'pending',
  "storage_path" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid,
  "error_message" varchar,
  "size_bytes" integer
);

CREATE TABLE "statements" (
  "submission_id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "upload_id" uuid NOT NULL,
  "description" varchar,
  "statement_date" date,
  "bank_name" varchar,
  "status" varchar NOT NULL DEFAULT 'processing',
  "processing_progress" integer DEFAULT 0,
  "error_message" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid,
  "insights_available" boolean DEFAULT false
);

CREATE TABLE "statement_tags" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "statement_id" uuid NOT NULL,
  "tag" varchar NOT NULL,
  "created_at" timestamp DEFAULT (now())
);

CREATE TABLE "insight_types" (
  "id" varchar PRIMARY KEY,
  "name" varchar NOT NULL,
  "description" text,
  "parameters" jsonb,
  "active" boolean DEFAULT true,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid
);

CREATE TABLE "insights" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "insight_type" varchar NOT NULL,
  "title" varchar NOT NULL,
  "summary" text,
  "data" jsonb NOT NULL,
  "generated_at" timestamp DEFAULT (now()),
  "parameters" jsonb,
  "custom" boolean DEFAULT false,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "insight_statement_links" (
  "insight_id" uuid NOT NULL,
  "statement_id" uuid NOT NULL,
  PRIMARY KEY ("insight_id", "statement_id")
);

CREATE TABLE "custom_insight_requests" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "prompt" text NOT NULL,
  "status" varchar NOT NULL DEFAULT 'pending',
  "progress" integer DEFAULT 0,
  "result_insight_id" uuid,
  "error_message" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "chat_sessions" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "title" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "last_message_at" timestamp
);

CREATE TABLE "chat_session_statements" (
  "session_id" uuid NOT NULL,
  "statement_id" uuid NOT NULL,
  PRIMARY KEY ("session_id", "statement_id")
);

CREATE TABLE "chat_messages" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "session_id" uuid NOT NULL,
  "role" varchar NOT NULL,
  "content" text NOT NULL,
  "created_at" timestamp DEFAULT (now()),
  "metadata" jsonb
);

CREATE TABLE "chat_message_attachments" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "message_id" uuid NOT NULL,
  "type" varchar NOT NULL,
  "reference_id" uuid NOT NULL,
  "created_at" timestamp DEFAULT (now())
);

CREATE TABLE "reports" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "report_type" varchar NOT NULL,
  "format" varchar NOT NULL,
  "title" varchar,
  "parameters" jsonb,
  "status" varchar NOT NULL DEFAULT 'processing',
  "progress" integer DEFAULT 0,
  "storage_path" varchar,
  "error_message" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid
);

CREATE TABLE "report_statement_links" (
  "report_id" uuid NOT NULL,
  "statement_id" uuid NOT NULL,
  PRIMARY KEY ("report_id", "statement_id")
);

CREATE TABLE "notifications" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "type" varchar NOT NULL,
  "title" varchar NOT NULL,
  "message" text NOT NULL,
  "read" boolean DEFAULT false,
  "read_at" timestamp,
  "data" jsonb,
  "created_at" timestamp DEFAULT (now()),
  "event_time" timestamp DEFAULT (now())
);

CREATE TABLE "user_preferences" (
  "user_id" uuid PRIMARY KEY,
  "display_preferences" jsonb NOT NULL DEFAULT '{}',
  "notification_preferences" jsonb NOT NULL DEFAULT '{}',
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid
);

CREATE TABLE "webhooks" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid NOT NULL,
  "url" varchar NOT NULL,
  "events" jsonb NOT NULL,
  "secret" varchar,
  "active" boolean DEFAULT true,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid
);

CREATE TABLE "webhook_deliveries" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "webhook_id" uuid NOT NULL,
  "event_type" varchar NOT NULL,
  "payload" jsonb NOT NULL,
  "status" varchar NOT NULL,
  "status_code" integer,
  "response_body" text,
  "error_message" varchar,
  "attempt_count" integer DEFAULT 1,
  "last_attempt_at" timestamp DEFAULT (now()),
  "created_at" timestamp DEFAULT (now()),
  "event_time" timestamp DEFAULT (now())
);

CREATE TABLE "audit_logs" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid,
  "action" varchar NOT NULL,
  "resource_type" varchar NOT NULL,
  "resource_id" uuid,
  "metadata" jsonb,
  "ip_address" varchar,
  "user_agent" varchar,
  "created_at" timestamp DEFAULT (now()),
  "event_time" timestamp DEFAULT (now())
);

CREATE TABLE "merchants" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "name" varchar NOT NULL,
  "normalized_name" varchar NOT NULL,
  "logo_url" varchar,
  "category_id" uuid,
  "metadata" jsonb,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "transactions" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "statement_id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "date" date NOT NULL,
  "description" text NOT NULL,
  "amount" decimal(15,2) NOT NULL,
  "type" varchar NOT NULL,
  "category_id" uuid,
  "merchant_id" uuid,
  "metadata" jsonb,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "transaction_categories" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "user_id" uuid,
  "name" varchar NOT NULL,
  "parent_id" uuid,
  "icon" varchar,
  "color" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now())
);

CREATE TABLE "transaction_tags" (
  "id" uuid PRIMARY KEY DEFAULT (uuid_generate_v4()),
  "transaction_id" uuid NOT NULL,
  "tag" varchar NOT NULL,
  "created_at" timestamp DEFAULT (now())
);

CREATE TABLE "system_settings" (
  "id" varchar PRIMARY KEY,
  "value" jsonb NOT NULL,
  "description" text,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp DEFAULT (now()),
  "updated_by" uuid,
  "version" integer NOT NULL DEFAULT 1
);

CREATE INDEX ON "users" ("email");

CREATE INDEX ON "refresh_tokens" ("token");

CREATE INDEX ON "refresh_tokens" ("user_id");

CREATE UNIQUE INDEX ON "oauth_accounts" ("provider", "provider_user_id");

CREATE INDEX ON "oauth_accounts" ("user_id");

CREATE INDEX ON "uploads" ("user_id");

CREATE INDEX ON "uploads" ("status");

CREATE INDEX ON "uploads" ("created_at");

CREATE INDEX ON "statements" ("user_id");

CREATE INDEX ON "statements" ("statement_date");

CREATE INDEX ON "statements" ("status");

CREATE INDEX ON "statements" ("created_at");

CREATE UNIQUE INDEX ON "statement_tags" ("statement_id", "tag");

CREATE INDEX ON "insights" ("user_id");

CREATE INDEX ON "insights" ("insight_type");

CREATE INDEX ON "insights" ("generated_at");

CREATE INDEX ON "custom_insight_requests" ("user_id");

CREATE INDEX ON "custom_insight_requests" ("status");

CREATE INDEX ON "custom_insight_requests" ("created_at");

CREATE INDEX ON "chat_sessions" ("user_id");

CREATE INDEX ON "chat_sessions" ("last_message_at");

CREATE INDEX ON "chat_messages" ("session_id");

CREATE INDEX ON "chat_messages" ("created_at");

CREATE INDEX ON "chat_message_attachments" ("message_id");

CREATE INDEX ON "reports" ("user_id");

CREATE INDEX ON "reports" ("status");

CREATE INDEX ON "reports" ("created_at");

CREATE INDEX ON "notifications" ("user_id");

CREATE INDEX ON "notifications" ("read");

CREATE INDEX ON "notifications" ("created_at");

CREATE INDEX ON "notifications" ("event_time");

CREATE INDEX ON "webhooks" ("user_id");

CREATE INDEX ON "webhooks" ("active");

CREATE INDEX ON "webhook_deliveries" ("webhook_id");

CREATE INDEX ON "webhook_deliveries" ("event_type");

CREATE INDEX ON "webhook_deliveries" ("created_at");

CREATE INDEX ON "webhook_deliveries" ("event_time");

CREATE INDEX ON "audit_logs" ("user_id");

CREATE INDEX ON "audit_logs" ("action");

CREATE INDEX ON "audit_logs" ("resource_type");

CREATE INDEX ON "audit_logs" ("created_at");

CREATE INDEX ON "audit_logs" ("event_time");

CREATE INDEX ON "merchants" ("normalized_name");

CREATE INDEX ON "transactions" ("statement_id");

CREATE INDEX ON "transactions" ("user_id");

CREATE INDEX ON "transactions" ("date");

CREATE INDEX ON "transactions" ("category_id");

CREATE INDEX ON "transactions" ("merchant_id");

CREATE INDEX ON "transactions" ("user_id", "date");

CREATE INDEX ON "transaction_categories" ("user_id");

CREATE INDEX ON "transaction_categories" ("name");

CREATE INDEX ON "transaction_categories" ("user_id", "parent_id");

CREATE UNIQUE INDEX ON "transaction_tags" ("transaction_id", "tag");

COMMENT ON TABLE "users" IS 'User accounts with authentication details and profile information';

COMMENT ON TABLE "refresh_tokens" IS 'JWT refresh tokens for maintaining user sessions';

COMMENT ON TABLE "oauth_accounts" IS 'OAuth provider connections for single sign-on';

COMMENT ON TABLE "uploads" IS 'Raw file uploads before processing into statements';

COMMENT ON TABLE "statements" IS 'Processed bank statements with metadata';

COMMENT ON TABLE "statement_tags" IS 'Tags applied to statements for organization';

COMMENT ON TABLE "insight_types" IS 'Catalog of available insight analysis types';

COMMENT ON TABLE "insights" IS 'Generated insights from statement analysis';

COMMENT ON TABLE "insight_statement_links" IS 'Maps insights to their source statements';

COMMENT ON TABLE "custom_insight_requests" IS 'User-requested custom insights to be processed';

COMMENT ON TABLE "chat_sessions" IS 'Chat conversation sessions';

COMMENT ON TABLE "chat_session_statements" IS 'Statements linked to chat sessions for context';

COMMENT ON TABLE "chat_messages" IS 'Individual messages within chat sessions';

COMMENT ON TABLE "chat_message_attachments" IS 'Files and references attached to chat messages';

COMMENT ON TABLE "reports" IS 'Generated reports for statements and insights';

COMMENT ON TABLE "report_statement_links" IS 'Maps reports to included statements';

COMMENT ON TABLE "notifications" IS 'User notifications for system events';

COMMENT ON TABLE "user_preferences" IS 'All user preferences including display, notification, and other settings';

COMMENT ON TABLE "webhooks" IS 'Registered webhook endpoints for event notifications';

COMMENT ON COLUMN "webhooks"."secret" IS 'Automatically regenerated on webhook update';

COMMENT ON TABLE "webhook_deliveries" IS 'History of webhook delivery attempts and results';

COMMENT ON TABLE "audit_logs" IS 'Comprehensive audit trail of system actions';

COMMENT ON TABLE "merchants" IS 'Centralized merchant database for consistent categorization';

COMMENT ON TABLE "transactions" IS 'Individual financial transactions extracted from statements';

COMMENT ON TABLE "transaction_categories" IS 'Hierarchical transaction categorization system';

COMMENT ON TABLE "transaction_tags" IS 'Tags applied to transactions for filtering and analysis';

COMMENT ON TABLE "system_settings" IS 'System-wide configuration settings';

ALTER TABLE "refresh_tokens" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "refresh_tokens" ADD FOREIGN KEY ("replaced_by") REFERENCES "refresh_tokens" ("id");

ALTER TABLE "oauth_accounts" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "uploads" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "uploads" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "statements" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "statements" ADD FOREIGN KEY ("upload_id") REFERENCES "uploads" ("id");

ALTER TABLE "statements" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "statement_tags" ADD FOREIGN KEY ("statement_id") REFERENCES "statements" ("submission_id");

ALTER TABLE "insight_types" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "insights" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "insights" ADD FOREIGN KEY ("insight_type") REFERENCES "insight_types" ("id");

ALTER TABLE "insight_statement_links" ADD FOREIGN KEY ("insight_id") REFERENCES "insights" ("id");

ALTER TABLE "insight_statement_links" ADD FOREIGN KEY ("statement_id") REFERENCES "statements" ("submission_id");

ALTER TABLE "custom_insight_requests" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "custom_insight_requests" ADD FOREIGN KEY ("result_insight_id") REFERENCES "insights" ("id");

ALTER TABLE "chat_sessions" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "chat_session_statements" ADD FOREIGN KEY ("session_id") REFERENCES "chat_sessions" ("id");

ALTER TABLE "chat_session_statements" ADD FOREIGN KEY ("statement_id") REFERENCES "statements" ("submission_id");

ALTER TABLE "chat_messages" ADD FOREIGN KEY ("session_id") REFERENCES "chat_sessions" ("id");

ALTER TABLE "chat_message_attachments" ADD FOREIGN KEY ("message_id") REFERENCES "chat_messages" ("id");

ALTER TABLE "reports" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "reports" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "report_statement_links" ADD FOREIGN KEY ("report_id") REFERENCES "reports" ("id");

ALTER TABLE "report_statement_links" ADD FOREIGN KEY ("statement_id") REFERENCES "statements" ("submission_id");

ALTER TABLE "notifications" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_preferences" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_preferences" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "webhooks" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "webhooks" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "webhook_deliveries" ADD FOREIGN KEY ("webhook_id") REFERENCES "webhooks" ("id");

ALTER TABLE "audit_logs" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "merchants" ADD FOREIGN KEY ("category_id") REFERENCES "transaction_categories" ("id");

ALTER TABLE "transactions" ADD FOREIGN KEY ("statement_id") REFERENCES "statements" ("submission_id");

ALTER TABLE "transactions" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "transactions" ADD FOREIGN KEY ("category_id") REFERENCES "transaction_categories" ("id");

ALTER TABLE "transactions" ADD FOREIGN KEY ("merchant_id") REFERENCES "merchants" ("id");

ALTER TABLE "transaction_categories" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "transaction_categories" ADD FOREIGN KEY ("parent_id") REFERENCES "transaction_categories" ("id");

ALTER TABLE "transaction_tags" ADD FOREIGN KEY ("transaction_id") REFERENCES "transactions" ("id");

ALTER TABLE "system_settings" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");
