-- +goose Up
CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    retries INTEGER DEFAULT 0,
    payload BLOB NOT NULL
);

-- +goose Down
DROP TABLE outbox;