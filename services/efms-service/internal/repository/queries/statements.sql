-- name: CreateStatement :one
INSERT INTO statements (
    user_id,
    upload_id,
    description,
    statement_date,
    bank_name,
    status,
    processing_progress,
    updated_by -- initially same as user_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $1
) RETURNING *;

-- name: GetStatementByIDAndUser :one
SELECT * FROM statements
WHERE submission_id = $1 AND user_id = $2;

-- name: GetStatementStatusByIDAndUser :one
SELECT submission_id, status, processing_progress, error_message, insights_available FROM statements
WHERE submission_id = $1 AND user_id = $2;

-- name: ListStatementsByUser :many
SELECT submission_id, statement_date, bank_name, status, created_at AS upload_date, insights_available
FROM statements
WHERE user_id = $1
AND ($2::varchar IS NULL OR status = $2::varchar)
AND ($3::date IS NULL OR statement_date >= $3::date)
AND ($4::date IS NULL OR statement_date <= $4::date)
-- TODO: Add tag filtering once statement_tags queries are in place and we decide on join strategy
ORDER BY created_at DESC
LIMIT $5 OFFSET $6;

-- name: UpdateStatementMetadataByIDAndUser :one
UPDATE statements
SET
    description = COALESCE(sqlc.arg(description), description),
    statement_date = COALESCE(sqlc.arg(statement_date), statement_date),
    bank_name = COALESCE(sqlc.arg(bank_name), bank_name),
    updated_at = now(),
    updated_by = sqlc.arg(updater_user_id) -- user_id of the updater
WHERE submission_id = sqlc.arg(submission_id) AND user_id = sqlc.arg(updater_user_id) -- Ensure user owns the statement
RETURNING *;

-- name: UpdateStatementStatusAndProgress :one
UPDATE statements
SET
    status = $2,
    processing_progress = $3,
    error_message = sqlc.narg('error_message'),
    insights_available = $4,
    updated_at = now()
    -- updated_by could be a system user ID or the original user ID
WHERE submission_id = $1
RETURNING *;

-- name: DeleteStatementByIDAndUser :exec
DELETE FROM statements
WHERE submission_id = $1 AND user_id = $2; 