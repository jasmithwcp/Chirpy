-- +goose Up
CREATE TABLE chirps (
  id UUID PRIMARY KEY, 
  user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE,
  body TEXT NOT NULL, 
  created_at TIMESTAMP NOT NULL, 
  updated_at TIMESTAMP NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users (id)
);

-- +goose Down
DROP TABLE chirps;