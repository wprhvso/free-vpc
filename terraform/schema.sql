CREATE TABLE IF NOT EXISTS runners (
  id TEXT PRIMARY KEY,
  run_id INTEGER,
  slot_id INTEGER UNIQUE,
  ip_gateway TEXT,
  subnet TEXT,
  status TEXT DEFAULT 'offline',
  started_at INTEGER,
  expires_at INTEGER,
  last_heartbeat INTEGER,
  zone TEXT
);

CREATE TABLE IF NOT EXISTS vms (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE,
  runner_id TEXT,
  slot_id INTEGER,
  ip TEXT UNIQUE,
  status TEXT DEFAULT 'standby',
  vcpus INTEGER DEFAULT 1,
  memory_mb INTEGER DEFAULT 1024,
  disk_gb INTEGER DEFAULT 10,
  image TEXT DEFAULT 'debian-12',
  ssh_keys TEXT,
  claimed_at INTEGER,
  key_synced INTEGER DEFAULT 0,
  created_at INTEGER,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS runner_tasks (
  id TEXT PRIMARY KEY,
  slot_id INTEGER,
  type TEXT,
  payload TEXT,
  status TEXT DEFAULT 'pending',
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE,
  hf_repo TEXT,
  hf_path TEXT,
  size_bytes INTEGER,
  sha256 TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS secrets (
  key_name TEXT PRIMARY KEY,
  encrypted_data TEXT,
  iv TEXT,
  created_at INTEGER,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY,
  name TEXT,
  role TEXT DEFAULT 'user',
  rate_limit_per_min INTEGER DEFAULT 60,
  created_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_vms_standby ON vms (status, slot_id);
CREATE INDEX IF NOT EXISTS idx_runners_status ON runners (status, last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_tasks_pending ON runner_tasks (slot_id, status);
