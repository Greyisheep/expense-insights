-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
  user_id, token_hash, expires_at
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: GetRefreshTokenByToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 AND revoked = false AND expires_at > now() LIMIT 1;

-- name: GetRefreshTokenByID :one
SELECT * FROM refresh_tokens
WHERE id = $1 LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = true, updated_at = now()
WHERE id = $1;

-- name: SetRefreshTokenReplacedBy :exec
UPDATE refresh_tokens
SET replaced_by = $2, updated_at = now()
WHERE id = $1;

-- name: GetRefreshTokensByUserID :many
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND revoked = false AND expires_at > now()
ORDER BY created_at DESC;

-- name: DeleteRefreshTokensByUserID :execrows
DELETE FROM refresh_tokens
WHERE user_id = $1;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens
WHERE expires_at <= now() OR revoked = true; 