import sys
import json
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Free VPC P2P Fleet</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0d14;
      --card: rgba(18, 24, 38, 0.7);
      --border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      padding: 2rem 1rem;
    }
    .container { max-width: 900px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    h1 { font-size: 1.5rem; font-weight: 700; }
    .badge {
      font-size: 0.75rem;
      padding: 0.25rem 0.6rem;
      border-radius: 9999px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
    }
    .badge-raft { background: rgba(59, 130, 246, 0.15); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-online { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
    .grid { display: grid; gap: 1rem; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      backdrop-filter: blur(8px);
    }
    .card:hover { border-color: rgba(255, 255, 255, 0.2); }
    .node-info { display: flex; align-items: center; gap: 1rem; }
    .slot-id {
      width: 42px; height: 42px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-family: 'JetBrains Mono', monospace; font-weight: 700;
    }
    .node-name { font-weight: 600; font-size: 1rem; }
    .node-mesh { font-size: 0.8rem; color: var(--muted); font-family: 'JetBrains Mono', monospace; }
    .actions { display: flex; gap: 0.5rem; }
    .btn {
      padding: 0.5rem 0.85rem;
      border-radius: 0.5rem;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      border: 1px solid transparent;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }
    .btn-primary { background: var(--primary); color: #fff; }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-secondary { background: rgba(255, 255, 255, 0.08); color: var(--text); border-color: var(--border); }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.15); }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Free VPC Cluster</h1>
        <p style="font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem;">Autonomous P2P Raft Fleet over Cloudflare Mesh</p>
      </div>
      <div style="display: flex; gap: 0.5rem; align-items: center;">
        <span class="badge badge-raft">rqlite Raft Core</span>
        <a href="/ssh" target="_blank" class="btn btn-primary">Open Web SSH</a>
      </div>
    </header>

    <div id="nodes" class="grid">
      <div style="text-align: center; padding: 3rem; color: var(--muted);">Loading cluster nodes...</div>
    </div>
  </div>

  <script>
    async function loadNodes() {
      try {
        const res = await fetch('/api/cluster');
        const data = await res.json();
        const container = document.getElementById('nodes');
        if (!data.runners || data.runners.length === 0) {
          container.innerHTML = '<div style="text-align: center; padding: 3rem; color: var(--muted);">No active nodes found. Initializing...</div>';
          return;
        }
        container.innerHTML = data.runners.map(r => `
          <div class="card">
            <div class="node-info">
              <div class="slot-id">#${r.slot_id}</div>
              <div>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                  <span class="node-name">${r.node_name || 'Node ' + r.slot_id}</span>
                  <span class="badge badge-online">online</span>
                </div>
                <div class="node-mesh">Mesh IP: ${r.mesh_ip || '100.96.x.x'} &middot; Cloudflare Mesh</div>
              </div>
            </div>
            <div class="actions">
              <a href="/ssh" target="_blank" class="btn btn-primary">Web SSH</a>
              <button onclick="navigator.clipboard.writeText('ssh -o ProxyCommand=\\\'cloudflared access ssh --hostname ssh.unsafie.com\\\' runner@ssh.unsafie.com'); alert('Copied SSH command!');" class="btn btn-secondary mono">CLI SSH</button>
            </div>
          </div>
        `).join('');
      } catch (err) {
        console.error(err);
      }
    }
    loadNodes();
    setInterval(loadNodes, 10000);
  </script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML.encode("utf-8"))
            return

        if self.path == "/api/cluster":
            runners = []
            try:
                req = urllib.request.Request(
                    "http://127.0.0.1:4001/db/query",
                    data=json.dumps([["SELECT slot_id, node_name, mesh_ip, web_url, ssh_url, status FROM runners WHERE status = 'online' ORDER BY slot_id ASC"]]).encode(),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    rows = data.get("results", [{}])[0].get("values", [])
                    for row in rows:
                        runners.append({
                            "slot_id": row[0],
                            "node_name": row[1],
                            "mesh_ip": row[2],
                            "web_url": row[3],
                            "ssh_url": row[4],
                            "status": row[5]
                        })
            except Exception:
                pass

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "runners": runners}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()
