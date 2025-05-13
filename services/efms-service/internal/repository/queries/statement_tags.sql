-- name: AddTagToStatement :one
INSERT INTO statement_tags (
    statement_id,
    tag
) VALUES (
    $1, $2
) RETURNING *;

-- name: GetTagsForStatement :many
SELECT tag FROM statement_tags
WHERE statement_id = $1
ORDER BY tag;

-- name: RemoveTagFromStatement :exec
DELETE FROM statement_tags
WHERE statement_id = $1 AND tag = $2;

-- name: RemoveAllTagsFromStatement :exec
DELETE FROM statement_tags
WHERE statement_id = $1;

-- name: ListStatementsByTagAndUser :many
SELECT s.submission_id, s.statement_date, s.bank_name, s.status, s.created_at AS upload_date, s.insights_available
FROM statements s
JOIN statement_tags st ON s.submission_id = st.statement_id
WHERE s.user_id = $1 AND st.tag = $2
AND ($3::varchar IS NULL OR s.status = $3::varchar)
AND ($4::date IS NULL OR s.statement_date >= $4::date)
AND ($5::date IS NULL OR s.statement_date <= $5::date)
ORDER BY s.created_at DESC
LIMIT $6 OFFSET $7; 