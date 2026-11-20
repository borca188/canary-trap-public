CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT UNIQUE NOT NULL,
    document_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    custom_path TEXT,
    callback_path TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    archived_at TEXT,
    FOREIGN KEY (token_id) REFERENCES tokens (token_id)
);

-- Keeps the per-token/IP rate check in events.log_event cheap.
CREATE INDEX IF NOT EXISTS idx_events_token_ip_ts ON events (token_id, ip_address, timestamp);

-- Hits dropped by the callback rate limit, aggregated per token, IP and window
-- so a flood costs one row, not one row per request.
CREATE TABLE IF NOT EXISTS suppressed_events (
    token_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    window_start TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, ip_address, window_start),
    FOREIGN KEY (token_id) REFERENCES tokens (token_id)
);
