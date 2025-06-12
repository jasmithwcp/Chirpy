-- name: GetRefreshToken :one
Select *
FROM refresh_tokens 
WHERE Token = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at, revoked_at)
VALUES ($1, $2, NOW(), NOW(), $3, NULL);

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET
    revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1;