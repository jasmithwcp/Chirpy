-- name: CreateChirp :one
INSERT INTO chirps (id, user_id, body, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    $1,
    $2,
    now(),
    now()
)
RETURNING *;

-- name: GetChirps :many
SELECT id, user_id, body, created_at, updated_at
FROM chirps 
    WHERE (user_id = $1 OR NOT $2)
ORDER BY created_at;

-- name: GetChirp :one
Select id, user_id, body, created_at, updated_at
FROM chirps WHERE id = $1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;