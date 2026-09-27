export default {
  async scheduled(event, env, ctx) {
    await checkAndSpawnMissing(env);
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/status") {
      const state = await getNodesState(env);
      return Response.json({
        ok: true,
        target: state.target,
        active_count: state.activeCount,
        running_ids: state.occupiedIds,
        missing_ids: state.missingIds,
        runs: state.runs
      });
    }

    if (url.pathname === "/spawn" && request.method === "POST") {
      const result = await checkAndSpawnMissing(env);
      return Response.json(result);
    }

    const state = await getNodesState(env);
    return new Response(
      `Free VPC Orchestrator. Active: ${state.activeCount} / ${state.target}. Running IDs: [${state.occupiedIds.join(", ")}]. Missing: [${state.missingIds.join(", ")}]`,
      { headers: { "Content-Type": "text/plain; charset=utf-8" } }
    );
  }
};

async function getNodesState(env) {
  const token = env.GITHUB_TOKEN;
  const repo = env.REPO || "wprhvso/free-vpc";
  const target = parseInt(env.TARGET_NODES || "20", 10);

  const [inProgRes, queuedRes] = await Promise.all([
    fetch(`https://api.github.com/repos/${repo}/actions/workflows/node.yml/runs?status=in_progress`, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "User-Agent": "FreeVPC-Worker",
        "Accept": "application/vnd.github.v3+json"
      }
    }),
    fetch(`https://api.github.com/repos/${repo}/actions/workflows/node.yml/runs?status=queued`, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "User-Agent": "FreeVPC-Worker",
        "Accept": "application/vnd.github.v3+json"
      }
    })
  ]);

  const inProgData = inProgRes.ok ? await inProgRes.json() : { workflow_runs: [] };
  const queuedData = queuedRes.ok ? await queuedRes.json() : { workflow_runs: [] };

  const allRuns = [...(inProgData.workflow_runs || []), ...(queuedData.workflow_runs || [])];

  const occupiedIds = new Set();
  const runDetails = [];

  for (const r of allRuns) {
    let nodeId = null;
    const match = (r.display_title || "").match(/node_id=(\d+)/) || (r.name || "").match(/node_id=(\d+)/);
    if (match) {
      nodeId = parseInt(match[1], 10);
    }
    runDetails.push({
      id: r.id,
      run_number: r.run_number,
      status: r.status,
      created_at: r.created_at,
      node_id: nodeId
    });
    if (nodeId) occupiedIds.add(nodeId);
  }

  let nextCandidate = 1;
  while (occupiedIds.size < allRuns.length && nextCandidate <= target) {
    if (!occupiedIds.has(nextCandidate)) {
      occupiedIds.add(nextCandidate);
    }
    nextCandidate++;
  }

  const missingIds = [];
  for (let i = 1; i <= target; i++) {
    if (!occupiedIds.has(i)) {
      missingIds.push(i);
    }
  }

  return {
    target,
    activeCount: allRuns.length,
    occupiedIds: Array.from(occupiedIds).sort((a, b) => a - b),
    missingIds,
    runs: runDetails
  };
}

async function spawnNode(env, nodeId) {
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
        node_id: String(nodeId)
      }
    })
  });
  return { node_id: nodeId, ok: res.status === 204, status: res.status };
}

async function checkAndSpawnMissing(env) {
  const state = await getNodesState(env);
  if (state.missingIds.length === 0) {
    return { ok: true, action: "none", target: state.target, active: state.activeCount };
  }

  const spawnPromises = state.missingIds.map(id => spawnNode(env, id));
  const results = await Promise.all(spawnPromises);

  return {
    ok: true,
    action: "spawned_missing",
    target: state.target,
    spawned_count: results.filter(r => r.ok).length,
    missing_ids_spawned: state.missingIds,
    results
  };
}
