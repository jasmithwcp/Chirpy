-- +goose Up
CREATE TABLE refresh_tokens (
  token TEXT PRIMARY KEY, 
  user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE, 
  created_at TIMESTAMP NOT NULL, 
  updated_at TIMESTAMP NOT NULL, 
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users (id)
);

-- +goose Down
DROP TABLE refresh_tokens;