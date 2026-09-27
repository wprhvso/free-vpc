export default {
  async scheduled(event, env, ctx) {
    await runWatchdog(env);
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return handleCors();
    }

    try {
      if (path === "/status") {
        return await handleStatus(request, env);
      }

      if (path === "/v1/vms") {
        if (method === "GET") return await handleListVms(request, env);
        if (method === "POST") return await handleCreateVm(request, env);
      }

      if (path.startsWith("/v1/vms/")) {
        const id = path.replace("/v1/vms/", "");
        if (method === "GET") return await handleGetVm(request, env, id);
        if (method === "DELETE") return await handleDeleteVm(request, env, id);
      }

      if (path === "/api/runner/boot" && method === "POST") {
        return await handleRunnerBoot(request, env);
      }

      if (path === "/api/runner/heartbeat" && method === "POST") {
        return await handleRunnerHeartbeat(request, env);
      }

      if (path === "/api/runner/handover" && method === "POST") {
        return await handleRunnerHandover(request, env);
      }

      if (path === "/v1/admin/secrets" && method === "POST") {
        return await handleSaveSecret(request, env);
      }

      if (path === "/v1/images") {
        if (method === "GET") return await handleListImages(request, env);
        if (method === "POST") return await handleCreateImage(request, env);
      }

      if (path === "/spawn" || path === "/check") {
        return await handleBatchSpawn(request, env);
      }

      return new Response(
        "Free VPC Orchestrator API v1\nEndpoints: /status, /v1/vms, /v1/images, /api/runner/boot, /api/runner/heartbeat, /api/runner/handover\n",
        {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    } catch (err) {
      return Response.json(
        { ok: false, error: err.message, stack: err.stack },
        { status: 500, headers: corsHeaders() }
      );
    }
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, If-None-Match"
  };
}

function handleCors() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function calculateSubnet(slot) {
  const s = parseInt(slot, 10);
  const x1 = 2 + Math.floor((s - 1) / 256);
  const x2 = (s - 1) % 256;
  return {
    slot_id: s,
    x1,
    x2,
    subnet: `10.${x1}.${x2}.0/24`,
    gateway_ip: `10.${x1}.${x2}.1`
  };
}

async function getMasterCryptoKey(env) {
  const secret = env.MASTER_KEY || "free-vpc-master-default-key-32b!";
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret.padEnd(32, "0").slice(0, 32)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("free-vpc-salt"),
      iterations: 10000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSecret(plainText, env) {
  const key = await getMasterCryptoKey(env);
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

async function decryptSecret(ciphertextB64, ivB64, env) {
  const key = await getMasterCryptoKey(env);
  const dec = new TextDecoder();
  const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  return dec.decode(decrypted);
}

async function hashString(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  const bytes = Array.from(new Uint8Array(buf));
  return bytes.map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

async function handleStatus(request, env) {
  const target = parseInt(env.TARGET_NODES || "20", 10);
  const runnersQuery = await env.DB.prepare("SELECT * FROM runners").all();
  const vmsQuery = await env.DB.prepare("SELECT * FROM vms").all();

  const now = Date.now();
  const activeRunners = (runnersQuery.results || []).filter(
    r => r.status === "online" && now - r.last_heartbeat < 90000
  );

  return Response.json(
    {
      ok: true,
      target,
      active_runners: activeRunners.length,
      total_vms: (vmsQuery.results || []).length,
      runners: runnersQuery.results || [],
      vms: vmsQuery.results || []
    },
    { headers: corsHeaders() }
  );
}

async function handleListVms(request, env) {
  const query = await env.DB.prepare("SELECT * FROM vms ORDER BY created_at DESC").all();
  const vms = query.results || [];
  const bodyStr = JSON.stringify({ ok: true, count: vms.length, vms });
  const etag = `"${await hashString(bodyStr)}"`;

  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, {
      status: 304,
      headers: { ...corsHeaders(), "ETag": etag }
    });
  }

  return new Response(bodyStr, {
    status: 200,
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json",
      "ETag": etag,
      "Cache-Control": "public, max-age=5"
    }
  });
}

async function handleGetVm(request, env, id) {
  const vm = await env.DB.prepare("SELECT * FROM vms WHERE id = ? OR name = ?").bind(id, id).first();
  if (!vm) {
    return Response.json({ ok: false, error: "VM not found" }, { status: 404, headers: corsHeaders() });
  }

  const bodyStr = JSON.stringify({ ok: true, vm });
  const etag = `"${await hashString(bodyStr)}"`;

  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, {
      status: 304,
      headers: { ...corsHeaders(), "ETag": etag }
    });
  }

  return new Response(bodyStr, {
    status: 200,
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json",
      "ETag": etag,
      "Cache-Control": "public, max-age=5"
    }
  });
}

async function handleCreateVm(request, env) {
  const payload = await request.json();
  const name = payload.name;
  if (!name) {
    return Response.json({ ok: false, error: "name is required" }, { status: 400, headers: corsHeaders() });
  }

  let slotId = payload.slot_id;
  if (!slotId) {
    const runner = await env.DB.prepare(
      "SELECT slot_id FROM runners WHERE status = 'online' ORDER BY slot_id ASC"
    ).first();
    slotId = runner ? runner.slot_id : 1;
  }

  const netInfo = calculateSubnet(slotId);

  const existingIpsQuery = await env.DB.prepare(
    "SELECT ip FROM vms WHERE slot_id = ?"
  ).bind(slotId).all();
  const takenIps = new Set((existingIpsQuery.results || []).map(r => r.ip));

  let assignedIp = null;
  for (let y = 2; y <= 254; y++) {
    const candidate = `10.${netInfo.x1}.${netInfo.x2}.${y}`;
    if (!takenIps.has(candidate)) {
      assignedIp = candidate;
      break;
    }
  }

  if (!assignedIp) {
    return Response.json(
      { ok: false, error: "No available IP addresses in runner subnet" },
      { status: 507, headers: corsHeaders() }
    );
  }

  const vmId = crypto.randomUUID();
  const now = Date.now();
  const vcpus = payload.vcpus || 1;
  const memoryMb = payload.memory_mb || 1024;
  const diskGb = payload.disk_gb || 10;
  const image = payload.image || "debian-12";
  const sshKeys = JSON.stringify(payload.ssh_keys || []);
  const runnerId = `runner-${slotId}`;

  await env.DB.prepare(
    `INSERT INTO vms (id, name, runner_id, slot_id, ip, status, vcpus, memory_mb, disk_gb, image, ssh_keys, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    vmId,
    name,
    runnerId,
    slotId,
    assignedIp,
    vcpus,
    memoryMb,
    diskGb,
    image,
    sshKeys,
    now,
    now
  ).run();

  const createdVm = {
    id: vmId,
    name,
    runner_id: runnerId,
    slot_id: slotId,
    ip: assignedIp,
    gateway: netInfo.gateway_ip,
    status: "running",
    vcpus,
    memory_mb: memoryMb,
    disk_gb: diskGb,
    image,
    created_at: now
  };

  return Response.json({ ok: true, vm: createdVm }, { status: 201, headers: corsHeaders() });
}

async function handleDeleteVm(request, env, id) {
  const result = await env.DB.prepare("DELETE FROM vms WHERE id = ? OR name = ?").bind(id, id).run();
  if (result.meta.changes === 0) {
    return Response.json({ ok: false, error: "VM not found" }, { status: 404, headers: corsHeaders() });
  }
  return Response.json({ ok: true, deleted: id }, { headers: corsHeaders() });
}

async function handleRunnerBoot(request, env) {
  const payload = await request.json();
  const runId = payload.run_id;
  const slotId = parseInt(payload.slot_id || "1", 10);
  const netInfo = calculateSubnet(slotId);
  const runnerId = `runner-${slotId}`;

  const now = Date.now();
  const expiresAt = now + 6 * 3600 * 1000;

  await env.DB.prepare(
    `INSERT INTO runners (id, run_id, slot_id, ip_gateway, subnet, status, started_at, expires_at, last_heartbeat, zone)
     VALUES (?, ?, ?, ?, ?, 'online', ?, ?, ?, ?)
     ON CONFLICT(slot_id) DO UPDATE SET
       id = excluded.id,
       run_id = excluded.run_id,
       ip_gateway = excluded.ip_gateway,
       subnet = excluded.subnet,
       status = 'online',
       started_at = excluded.started_at,
       expires_at = excluded.expires_at,
       last_heartbeat = excluded.last_heartbeat,
       zone = excluded.zone`
  ).bind(
    runnerId,
    runId,
    slotId,
    netInfo.gateway_ip,
    netInfo.subnet,
    now,
    expiresAt,
    now,
    `az-${slotId}`
  ).run();

  const vmsQuery = await env.DB.prepare(
    "SELECT * FROM vms WHERE slot_id = ?"
  ).bind(slotId).all();

  return Response.json({
    ok: true,
    runner_id: runnerId,
    slot_id: slotId,
    gateway_ip: netInfo.gateway_ip,
    subnet: netInfo.subnet,
    vms: vmsQuery.results || []
  }, { headers: corsHeaders() });
}

async function handleRunnerHeartbeat(request, env) {
  const payload = await request.json();
  const slotId = parseInt(payload.slot_id, 10);
  const now = Date.now();

  await env.DB.prepare(
    "UPDATE runners SET last_heartbeat = ?, status = 'online' WHERE slot_id = ?"
  ).bind(now, slotId).run();

  return Response.json({ ok: true, timestamp: now }, { headers: corsHeaders() });
}

async function handleRunnerHandover(request, env) {
  const payload = await request.json();
  const slotId = parseInt(payload.slot_id, 10);

  await env.DB.prepare(
    "UPDATE runners SET status = 'draining' WHERE slot_id = ?"
  ).bind(slotId).run();

  const spawnRes = await dispatchGitHubRunner(env, slotId);

  return Response.json({
    ok: true,
    action: "handover_initiated",
    slot_id: slotId,
    spawn_result: spawnRes
  }, { headers: corsHeaders() });
}

async function handleSaveSecret(request, env) {
  const payload = await request.json();
  const keyName = payload.key_name;
  const secretValue = payload.value;

  if (!keyName || !secretValue) {
    return Response.json({ ok: false, error: "key_name and value are required" }, { status: 400, headers: corsHeaders() });
  }

  const { ciphertext, iv } = await encryptSecret(secretValue, env);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO secrets (key_name, encrypted_data, iv, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(key_name) DO UPDATE SET
       encrypted_data = excluded.encrypted_data,
       iv = excluded.iv,
       updated_at = excluded.updated_at`
  ).bind(keyName, ciphertext, iv, now, now).run();

  return Response.json({ ok: true, saved_key: keyName }, { status: 201, headers: corsHeaders() });
}

async function handleListImages(request, env) {
  const query = await env.DB.prepare("SELECT * FROM images ORDER BY name ASC").all();
  return Response.json({ ok: true, images: query.results || [] }, { headers: corsHeaders() });
}

async function handleCreateImage(request, env) {
  const payload = await request.json();
  const id = crypto.randomUUID();
  const name = payload.name;
  const hfRepo = payload.hf_repo;
  const hfPath = payload.hf_path;
  const sizeBytes = payload.size_bytes || 0;
  const sha256 = payload.sha256 || "";
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO images (id, name, hf_repo, hf_path, size_bytes, sha256, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, name, hfRepo, hfPath, sizeBytes, sha256, now).run();

  return Response.json({ ok: true, image: { id, name, hf_repo: hfRepo, hf_path: hfPath } }, { status: 201, headers: corsHeaders() });
}

async function dispatchGitHubRunner(env, slotId) {
  const token = env.GITHUB_TOKEN;
  const repo = env.REPO || "wprhvso/free-vpc";
  const branch = env.BRANCH || "init-free-vpc";

  const res = await fetch(`https://api.github.com/repos/${repo}/actions/workflows/node.yml/dispatches`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "User-Agent": "FreeVPC-Worker",
      "Accept": "application/vnd.github.v3+json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ref: branch,
      inputs: {
        node_id: String(slotId)
      }
    })
  });
  return { slot_id: slotId, ok: res.status === 204, status: res.status };
}

async function runWatchdog(env) {
  const target = parseInt(env.TARGET_NODES || "20", 10);
  const now = Date.now();

  const deadRunners = await env.DB.prepare(
    "SELECT slot_id FROM runners WHERE status = 'online' AND (? - last_heartbeat) > 90000"
  ).bind(now).all();

  for (const r of (deadRunners.results || [])) {
    await env.DB.prepare("UPDATE runners SET status = 'offline' WHERE slot_id = ?").bind(r.slot_id).run();
    await dispatchGitHubRunner(env, r.slot_id);
  }

  const activeRunners = await env.DB.prepare(
    "SELECT slot_id FROM runners WHERE status = 'online' AND (? - last_heartbeat) <= 90000"
  ).bind(now).all();

  const occupiedSlots = new Set((activeRunners.results || []).map(r => r.slot_id));
  for (let s = 1; s <= target; s++) {
    if (!occupiedSlots.has(s)) {
      await dispatchGitHubRunner(env, s);
    }
  }
}

async function handleBatchSpawn(request, env) {
  const target = parseInt(env.TARGET_NODES || "20", 10);
  const now = Date.now();

  const active = await env.DB.prepare(
    "SELECT slot_id FROM runners WHERE status = 'online' AND (? - last_heartbeat) <= 90000"
  ).bind(now).all();

  const occupied = new Set((active.results || []).map(r => r.slot_id));
  const missing = [];
  for (let s = 1; s <= target; s++) {
    if (!occupied.has(s)) {
      missing.push(s);
    }
  }

  const spawnPromises = missing.map(s => dispatchGitHubRunner(env, s));
  const results = await Promise.all(spawnPromises);

  return Response.json({
    ok: true,
    action: "batch_spawn",
    target,
    missing_slots: missing,
    spawned_count: results.filter(r => r.ok).length,
    results
  }, { headers: corsHeaders() });
}
