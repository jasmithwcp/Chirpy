-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1, 
    $2
)
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetUser :one
SELECT * FROM users where email = $1;

-- name: UpdateUser :one
UPDATE users SET 
    email = $1, 
    hashed_password = $2, 
    updated_at = NOW() 
WHERE id = $3 
RETURNING *;

-- name: EnrollInChirpyRed :exec
UPDATE users SET
    is_chirpy_red = true
WHERE id = $1;