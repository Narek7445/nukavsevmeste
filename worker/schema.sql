CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO app_state (key, value, updated_at)
VALUES ('participants', '[]', datetime('now'))
ON CONFLICT(key) DO NOTHING;
