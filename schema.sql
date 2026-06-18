CREATE TABLE IF NOT EXISTS hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT,
  ip TEXT,
  asn TEXT,
  country TEXT,
  user_agent TEXT,
  method TEXT,
  path TEXT,
  headers TEXT,
  body TEXT,
  cf_threat_score INTEGER,
  cf_bot_score INTEGER
);
