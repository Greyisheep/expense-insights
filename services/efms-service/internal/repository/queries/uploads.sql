-- name: CreateUpload :one
INSERT INTO uploads (
    user_id,
    file_name,
    content_type,
    size_bytes,
    status
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetUpload :one
SELECT * FROM uploads
WHERE id = $1 AND user_id = $2;

-- name: GetUploadByFileNameAndUser :one
SELECT * FROM uploads
WHERE file_name = $1 AND user_id = $2 AND status = 'pending'; -- Or any other relevant status

-- name: UpdateUploadStatus :one
UPDATE uploads
SET
    status = $2,
    storage_path = $3,
    updated_at = now(),
    error_message = $4
WHERE id = $1 AND user_id = $5
RETURNING *;

-- name: DeleteUpload :exec
DELETE FROM uploads
WHERE id = $1 AND user_id = $2; 