export default {
  async scheduled(event, env, ctx) {
    await checkAndSpawn(env);
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      const runs = await getActiveRuns(env);
      return Response.json({
        ok: true,
        active_nodes: runs.length,
        nodes: runs
      });
    }

    if (url.pathname === "/spawn" && request.method === "POST") {
      const result = await spawnNode(env);
      return Response.json(result);
    }

    if (url.pathname === "/check") {
      const result = await checkAndSpawn(env);
      return Response.json(result);
    }

    const runs = await getActiveRuns(env);
    return new Response(
      `Free VPC Orchestrator Online. Active nodes: ${runs.length}`,
      { headers: { "Content-Type": "text/plain" } }
    );
  }
};

async function getActiveRuns(env) {
  const token = env.GITHUB_TOKEN;
  const repo = env.REPO || "wprhvso/free-vpc";
  const res = await fetch(
    `https://api.github.com/repos/${repo}/actions/workflows/node.yml/runs?status=in_progress`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
        "User-Agent": "FreeVPC-Worker",
        "Accept": "application/vnd.github.v3+json"
      }
    }
  );
  if (!res.ok) return [];
  const data = await res.json();
  return (data.workflow_runs || []).map(r => ({
    id: r.id,
    run_number: r.run_number,
    status: r.status,
    created_at: r.created_at,
    html_url: r.html_url
  }));
}

async function spawnNode(env) {
  const token = env.GITHUB_TOKEN;
  const repo = env.REPO || "wprhvso/free-vpc";
  const res = await fetch(
    `https://api.github.com/repos/${repo}/actions/workflows/node.yml/dispatches`,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "User-Agent": "FreeVPC-Worker",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ref: "init-free-vpc" })
    }
  );
  return { ok: res.status === 204, status: res.status };
}

async function checkAndSpawn(env) {
  const target = parseInt(env.TARGET_NODES || "1", 10);
  const runs = await getActiveRuns(env);
  if (runs.length < target) {
    const spawned = await spawnNode(env);
    return { ok: true, action: "spawned", target, current: runs.length, spawned };
  }
  return { ok: true, action: "none", target, current: runs.length };
}
