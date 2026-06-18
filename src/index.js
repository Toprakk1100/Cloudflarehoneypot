export default {
  async fetch(request, env) {
    const cf = request.cf || {};
    const url = new URL(request.url);

    let body = "";
    try {
      body = await request.text();
    } catch {}

    if (url.pathname === "/logs") {
  const key = url.searchParams.get("key");
  if (key !== env.VIEWER_KEY) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  const { results } = await env.DB.prepare(
    "SELECT * FROM hits ORDER BY timestamp DESC LIMIT 100"
  ).all();
  return Response.json(results);
}

if (url.pathname === "/dashboard") {
  const key = url.searchParams.get("key");
  if (key !== env.VIEWER_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  const { results } = await env.DB.prepare(
    "SELECT * FROM hits ORDER BY timestamp DESC LIMIT 100"
  ).all();

  const rows = results.map(h => `
    <tr>
      <td>${h.timestamp}</td>
      <td>${h.ip}</td>
      <td>${h.country || "-"}</td>
      <td>${h.path}</td>
      <td>${h.method}</td>
      <td>${h.user_agent || "-"}</td>
      <td>${h.cf_bot_score ?? "-"}</td>
      <td>${h.cf_threat_score ?? "-"}</td>
    </tr>
  `).join("");

  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Honeypot Dashboard</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #58a6ff; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #161b22; color: #58a6ff; padding: 8px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #21262d; word-break: break-all; }
    tr:hover { background: #161b22; }
    .high { color: #f85149; font-weight: bold; }
  </style>
</head>
<body>
  <h1>🍯 Honeypot Hits</h1>
  <p>${results.length} most recent hits</p>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th><th>IP</th><th>Country</th><th>Path</th>
        <th>Method</th><th>User Agent</th><th>Bot Score</th><th>Threat Score</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

    await env.DB.prepare(`
      INSERT INTO hits (timestamp, ip, asn, country, user_agent, method, path, headers, body, cf_threat_score, cf_bot_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      new Date().toISOString(),
      cf.ip || request.headers.get("cf-connecting-ip") || "unknown",
      cf.asn || null,
      cf.country || null,
      request.headers.get("user-agent") || null,
      request.method,
      url.pathname,
      JSON.stringify(Object.fromEntries(request.headers)),
      body,
      cf.threatScore || null,
      cf.botManagement?.score || null,
    ).run();

    if (url.pathname === "/api/v1/login") {
      return Response.json({ error: "Invalid credentials" }, { status: 401 });
    } else if (url.pathname === "/admin") {
      return Response.json({ error: "Forbidden" }, { status: 403 });
    } else if (url.pathname === "/health") {
      return Response.json({ status: "ok" });
    } else {
      return Response.json({ error: "Not found" }, { status: 404 });
    }
  }
};
